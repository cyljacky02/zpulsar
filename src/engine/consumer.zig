//! The ETW consumer thread (ADR-0002 thread 2): blocked in ProcessTrace on
//! the `zPulsarNet` real-time session, parse-only — every event becomes a
//! fixed-size record pushed onto an SPSC ring, or nothing. Dispatch is on
//! the provider GUID first (Kernel-Network and Kernel-Process share the
//! session), then on (event id, version). Known layouts take the
//! fixed-offset hot path; unknown versions route to the TDH fallbacks. The
//! shared wake event is set exactly on either ring's empty→non-empty
//! transition.

const std = @import("std");
const win32 = @import("win32");
const dns_parser = @import("dns_parser.zig");
const etw_session = @import("etw_session.zig");
const event = @import("event.zig");
const parser = @import("parser.zig");
const process_parser = @import("process_parser.zig");
const process_tdh = @import("process_tdh.zig");
const spsc_ring = @import("spsc_ring.zig");
const sync = @import("sync.zig");
const tdh = @import("tdh.zig");

/// Spec issue #18: power-of-two 16 Ki × ~64 B records (~1 MiB, heap).
pub const ring_capacity = 16 * 1024;
pub const Ring = spsc_ring.SpscRing(event.NetEvent, ring_capacity);

/// Process events are ~600 B but low-volume; the capacity's real job is
/// absorbing the CAPTURE_STATE rundown burst (one event per live process,
/// ~500 on a busy desktop) even if the Engine never drains during it.
pub const process_ring_capacity = 1024;
pub const ProcessRing = spsc_ring.SpscRing(event.ProcessEvent, process_ring_capacity);

/// Completed resolutions run at ~4 events/s on an idle desktop
/// (docs/research/dns-client-etw.md §6) and the Engine drains every flush
/// tick, so this is orders of magnitude of headroom. Overflow would cost
/// names, never bytes: the affected Flows fall through to the reverse-lookup
/// lane, which is why DNS drops stay out of the totals loss signal.
pub const dns_ring_capacity = 128;
pub const DnsRing = spsc_ring.SpscRing(event.DnsEvent, dns_ring_capacity);

/// The unknown-version seam: production asks TDH per event (process_tdh);
/// tests inject a fake.
pub const ProcessFallbackFn = *const fn (
    rec: *win32.EVENT_RECORD,
    kind: event.ProcessKind,
) ?event.ProcessEvent;

pub const Consumer = struct {
    ring: *Ring,
    process_ring: *ProcessRing,
    dns_ring: *DnsRing,
    wake: sync.WakeEvent,
    fallback: tdh.FallbackCache,
    process_fallback: ProcessFallbackFn = process_tdh.parse,
    trace: win32.PROCESSTRACE_HANDLE = win32.INVALID_PROCESSTRACE_HANDLE,
    /// OpenTraceW may write into the logfile struct; the name buffer must
    /// outlive the ProcessTrace call.
    name_buf: [etw_session.session_name_w.len:0]u16 = etw_session.session_name_w.*,

    pub fn init(
        ring: *Ring,
        process_ring: *ProcessRing,
        dns_ring: *DnsRing,
        wake: sync.WakeEvent,
        gpa: std.mem.Allocator,
    ) Consumer {
        return .{
            .ring = ring,
            .process_ring = process_ring,
            .dns_ring = dns_ring,
            .wake = wake,
            .fallback = .init(gpa),
        };
    }

    pub fn deinit(self: *Consumer) void {
        self.fallback.deinit();
    }

    /// Open the real-time consumer handle against the session by name. The
    /// Consumer's address must be stable from here on (callback context).
    pub fn open(self: *Consumer) error{OpenFailed}!void {
        var logfile = std.mem.zeroes(win32.EVENT_TRACE_LOGFILEW);
        logfile.LoggerName = &self.name_buf;
        logfile.Anonymous1.ProcessTraceMode =
            win32.PROCESS_TRACE_MODE_REAL_TIME | win32.PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = eventRecordCallback;
        logfile.Context = self;
        const handle = win32.OpenTraceW(&logfile);
        if (handle == win32.INVALID_PROCESSTRACE_HANDLE) return error.OpenFailed;
        self.trace = handle;
    }

    /// Blocks the calling thread until the handle is closed or the session
    /// stops (thread body).
    pub fn run(self: *Consumer) void {
        var handles = [_]win32.PROCESSTRACE_HANDLE{self.trace};
        _ = win32.ProcessTrace(&handles, 1, null, null);
    }

    /// Marks the handle for teardown; ProcessTrace returns after the current
    /// buffer. Pair with the session stop, which unblocks it deterministically.
    pub fn close(self: *Consumer) void {
        if (self.trace == win32.INVALID_PROCESSTRACE_HANDLE) return;
        _ = win32.CloseTrace(self.trace);
        self.trace = win32.INVALID_PROCESSTRACE_HANDLE;
    }

    fn eventRecordCallback(rec_opt: ?*win32.EVENT_RECORD) callconv(.winapi) void {
        const rec = rec_opt orelse return;
        const ctx = rec.UserContext orelse return;
        const self: *Consumer = @ptrCast(@alignCast(ctx));
        self.handleRecord(rec);
    }

    /// Provider dispatch. The session also delivers ETW's own control events
    /// (e.g. the EventTrace header); anything but our three providers is
    /// ignored.
    fn handleRecord(self: *Consumer, rec: *win32.EVENT_RECORD) void {
        const provider = &rec.EventHeader.ProviderId.Bytes;
        if (std.mem.eql(u8, provider, &etw_session.kernel_network_guid.Bytes)) {
            self.handleNetRecord(rec);
        } else if (std.mem.eql(u8, provider, &etw_session.kernel_process_guid.Bytes)) {
            self.handleProcessRecord(rec);
        } else if (std.mem.eql(u8, provider, &etw_session.dns_client_guid.Bytes)) {
            self.handleDnsRecord(rec);
        }
    }

    /// The per-event Kernel-Network hot path. The attribution PID comes from
    /// the payload inside parse — the header PID is never read
    /// (etw-tcp-udp-pipeline research §2.3).
    fn handleNetRecord(self: *Consumer, rec: *win32.EVENT_RECORD) void {
        const ts = rec.EventHeader.TimeStamp.QuadPart;
        const desc = rec.EventHeader.EventDescriptor;
        const parsed = if (desc.Version == 0)
            parser.parseV0(desc.Id, userData(rec), ts)
        else
            self.fallback.parse(rec, userData(rec), ts);
        const ev = parsed orelse return;
        if (self.ring.push(ev) == .pushed_was_empty) self.wake.set();
    }

    /// Kernel-Process start/stop/rundown → the process ring. Unknown
    /// versions must never touch the fixed offsets (fields were inserted,
    /// not appended) — they go to the TDH fallback.
    fn handleProcessRecord(self: *Consumer, rec: *win32.EVENT_RECORD) void {
        const desc = rec.EventHeader.EventDescriptor;
        const ev = switch (process_parser.parse(desc.Id, desc.Version, userData(rec))) {
            .event => |ev| ev,
            .drop => return,
            .unknown_version => |kind| self.process_fallback(rec, kind) orelse return,
        };
        if (self.process_ring.push(ev) == .pushed_was_empty) self.wake.set();
    }

    /// DNS-Client 3008 → the DNS ring. Unlike the other two providers, the
    /// attribution PID is the *header* PID: 3008 is emitted in-process by
    /// dnsapi.dll and has no PID payload field (research §2). The provider's
    /// other 3000-series events are enabled along with it and drop here.
    fn handleDnsRecord(self: *Consumer, rec: *win32.EVENT_RECORD) void {
        const desc = rec.EventHeader.EventDescriptor;
        const ev = dns_parser.parse(
            desc.Id,
            desc.Version,
            rec.EventHeader.ProcessId,
            userData(rec),
        ) orelse return;
        if (self.dns_ring.push(ev) == .pushed_was_empty) self.wake.set();
    }

    fn userData(rec: *win32.EVENT_RECORD) []const u8 {
        const p = rec.UserData orelse return &.{};
        return @as([*]const u8, @ptrCast(p))[0..rec.UserDataLength];
    }
};

// ---------------------------------------------------------------------------
// Tests — dispatch only; the live ProcessTrace path needs elevation and runs
// through the headless rig.
// ---------------------------------------------------------------------------

const TestRig = struct {
    ring: *Ring,
    process_ring: *ProcessRing,
    dns_ring: *DnsRing,
    wake: sync.WakeEvent,
    consumer: Consumer,

    fn init() !*TestRig {
        const gpa = std.testing.allocator;
        const self = try gpa.create(TestRig);
        errdefer gpa.destroy(self);
        self.ring = try gpa.create(Ring);
        errdefer gpa.destroy(self.ring);
        self.ring.* = .{};
        self.process_ring = try gpa.create(ProcessRing);
        errdefer gpa.destroy(self.process_ring);
        self.process_ring.* = .{};
        self.dns_ring = try gpa.create(DnsRing);
        errdefer gpa.destroy(self.dns_ring);
        self.dns_ring.* = .{};
        self.wake = try sync.WakeEvent.init();
        self.consumer = Consumer.init(self.ring, self.process_ring, self.dns_ring, self.wake, gpa);
        return self;
    }

    fn deinit(self: *TestRig) void {
        const gpa = std.testing.allocator;
        self.consumer.deinit();
        self.wake.deinit();
        gpa.destroy(self.dns_ring);
        gpa.destroy(self.process_ring);
        gpa.destroy(self.ring);
        gpa.destroy(self);
    }
};

fn testRecord(
    provider: win32.Guid,
    id: u16,
    version: u8,
    payload: []const u8,
    consumer: *Consumer,
) win32.EVENT_RECORD {
    var rec = std.mem.zeroes(win32.EVENT_RECORD);
    rec.EventHeader.ProviderId = provider;
    rec.EventHeader.EventDescriptor.Id = id;
    rec.EventHeader.EventDescriptor.Version = version;
    rec.EventHeader.TimeStamp.QuadPart = 12345;
    rec.UserData = @constCast(@ptrCast(payload.ptr));
    rec.UserDataLength = @intCast(payload.len);
    rec.UserContext = consumer;
    return rec;
}

/// A valid v0 TCPv4-recv payload: PID, size, daddr, saddr, dport, sport.
const net_payload = blk: {
    var b: [20]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], 4242, .little);
    std.mem.writeInt(u32, b[4..8], 100, .little);
    std.mem.writeInt(u16, b[16..18], 443, .big);
    std.mem.writeInt(u16, b[18..20], 51000, .big);
    break :blk b;
};

/// A valid 1v2/15v0 start-shape payload: PID, CreateTime, ParentPID,
/// SessionID, Flags, ImageName "\x\a.exe".
const process_start_payload = blk: {
    var b: [24 + 16 + 2]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], 7777, .little);
    std.mem.writeInt(u64, b[4..12], 0xAA55, .little);
    for ("\\x\\a.exe", 0..) |c, i| b[24 + 2 * i] = c;
    break :blk b;
};

/// A valid 2v1 stop payload prefix: PID, CreateTime, ExitTime, ExitCode.
const process_stop_payload = blk: {
    var b: [24]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], 7777, .little);
    std.mem.writeInt(u64, b[4..12], 0xAA55, .little);
    std.mem.writeInt(u64, b[12..20], 0xAA99, .little);
    break :blk b;
};

/// A valid 3008 v0 payload: QueryName "example.com", QueryType, QueryOptions,
/// QueryStatus 0, QueryResults "93.184.216.34;".
const dns_payload = blk: {
    const name = "example.com";
    const results = "93.184.216.34;";
    var b: [2 * name.len + 2 + 16 + 2 * results.len + 2]u8 = @splat(0);
    for (name, 0..) |c, i| b[2 * i] = c;
    std.mem.writeInt(u32, b[2 * name.len + 2 ..][0..4], 28, .little); // QueryType
    // QueryOptions (u64) and QueryStatus (u32) stay zero — success.
    for (results, 0..) |c, i| b[2 * name.len + 2 + 16 + 2 * i] = c;
    break :blk b;
};

var test_fallback_calls: u32 = 0;

fn testFallbackDerive(rec: *win32.EVENT_RECORD, gpa: std.mem.Allocator) ?tdh.FieldOffsets {
    _ = rec;
    _ = gpa;
    test_fallback_calls += 1;
    return tdh.test_v4_offsets;
}

var test_process_fallback_calls: u32 = 0;

fn testProcessFallback(rec: *win32.EVENT_RECORD, kind: event.ProcessKind) ?event.ProcessEvent {
    _ = rec;
    test_process_fallback_calls += 1;
    return .{
        .kind = kind,
        .pid = 31337,
        .create_time = 42,
        .exit_time = 0,
        .name_len = 0,
        .name_buf = undefined,
    };
}

test "version 0 net events take the fixed-offset path and land on the ring" {
    const rig = try TestRig.init();
    defer rig.deinit();
    rig.consumer.fallback.derive = &testFallbackDerive;
    test_fallback_calls = 0;

    var rec = testRecord(etw_session.kernel_network_guid, parser.Id.tcp4_recv, 0, &net_payload, &rig.consumer);
    Consumer.eventRecordCallback(&rec);

    try std.testing.expectEqual(@as(u32, 0), test_fallback_calls);
    const ev = rig.ring.pop() orelse return error.NothingPushed;
    try std.testing.expectEqual(@as(u32, 4242), ev.pid);
    try std.testing.expectEqual(@as(u32, 100), ev.size);
    try std.testing.expectEqual(@as(i64, 12345), ev.timestamp_ft);
    // Empty→non-empty push must have set the wake event.
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, rig.wake.timedWait(0));
}

test "unknown net versions route to the TDH-derived fallback" {
    const rig = try TestRig.init();
    defer rig.deinit();
    rig.consumer.fallback.derive = &testFallbackDerive;
    test_fallback_calls = 0;

    var rec = testRecord(etw_session.kernel_network_guid, parser.Id.tcp4_recv, 1, &net_payload, &rig.consumer);
    Consumer.eventRecordCallback(&rec);
    Consumer.eventRecordCallback(&rec);

    try std.testing.expectEqual(@as(u32, 1), test_fallback_calls); // derived once
    try std.testing.expectEqual(@as(u32, 4242), rig.ring.pop().?.pid);
    try std.testing.expectEqual(@as(u32, 4242), rig.ring.pop().?.pid);
}

test "kernel-process events parse onto the process ring and wake the engine" {
    const rig = try TestRig.init();
    defer rig.deinit();

    var start = testRecord(etw_session.kernel_process_guid, 1, 2, &process_start_payload, &rig.consumer);
    Consumer.eventRecordCallback(&start);
    var stop = testRecord(etw_session.kernel_process_guid, 2, 1, &process_stop_payload, &rig.consumer);
    Consumer.eventRecordCallback(&stop);

    try std.testing.expect(rig.ring.isEmpty()); // never the net ring
    const s = rig.process_ring.pop() orelse return error.NothingPushed;
    try std.testing.expectEqual(event.ProcessKind.start, s.kind);
    try std.testing.expectEqual(@as(u32, 7777), s.pid);
    try std.testing.expectEqual(@as(u64, 0xAA55), s.create_time);
    try std.testing.expectEqual(@as(usize, 8), s.name().len);
    const x = rig.process_ring.pop() orelse return error.NothingPushed;
    try std.testing.expectEqual(event.ProcessKind.stop, x.kind);
    try std.testing.expectEqual(@as(u64, 0xAA99), x.exit_time);
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, rig.wake.timedWait(0));
}

test "unknown kernel-process versions route to the process TDH fallback" {
    const rig = try TestRig.init();
    defer rig.deinit();
    rig.consumer.process_fallback = &testProcessFallback;
    test_process_fallback_calls = 0;

    var rec = testRecord(etw_session.kernel_process_guid, 15, 9, &process_start_payload, &rig.consumer);
    Consumer.eventRecordCallback(&rec);

    try std.testing.expectEqual(@as(u32, 1), test_process_fallback_calls);
    const ev = rig.process_ring.pop() orelse return error.NothingPushed;
    try std.testing.expectEqual(event.ProcessKind.rundown, ev.kind);
    try std.testing.expectEqual(@as(u32, 31337), ev.pid);
}

test "DNS-Client 3008 lands on the DNS ring, attributed to the header PID" {
    const rig = try TestRig.init();
    defer rig.deinit();

    var rec = testRecord(etw_session.dns_client_guid, dns_parser.Id.query_completed, 0, &dns_payload, &rig.consumer);
    // 3008 is emitted in-process: the header PID is the querying process.
    rec.EventHeader.ProcessId = 42576;
    Consumer.eventRecordCallback(&rec);

    try std.testing.expect(rig.ring.isEmpty());
    try std.testing.expect(rig.process_ring.isEmpty());
    const ev = rig.dns_ring.pop() orelse return error.NothingPushed;
    try std.testing.expectEqual(@as(u32, 42576), ev.pid);
    try std.testing.expectEqualStrings("example.com", ev.name());
    try std.testing.expectEqual(@as(usize, 1), ev.addresses().len);
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, rig.wake.timedWait(0));
}

test "foreign providers and excluded events never reach any ring" {
    const rig = try TestRig.init();
    defer rig.deinit();
    rig.consumer.process_fallback = &testProcessFallback;
    test_process_fallback_calls = 0;

    const foreign_guid = win32.Guid.initString("00000000-0000-0000-0000-000000000001");
    var foreign = testRecord(foreign_guid, parser.Id.tcp4_recv, 0, &net_payload, &rig.consumer);
    Consumer.eventRecordCallback(&foreign);

    var retransmit = testRecord(etw_session.kernel_network_guid, parser.Id.tcp4_retransmit, 0, &net_payload, &rig.consumer);
    Consumer.eventRecordCallback(&retransmit);

    // Id 27 (ProcessInPrivateSet) shares keyword 0x10: dropped, not TDH'd.
    var private_set = testRecord(etw_session.kernel_process_guid, 27, 0, &process_start_payload, &rig.consumer);
    Consumer.eventRecordCallback(&private_set);

    // The DNS provider is enabled on all keywords, so its other 3000-series
    // events arrive too — and drop here rather than at the session.
    var query_called = testRecord(etw_session.dns_client_guid, 3006, 0, &dns_payload, &rig.consumer);
    Consumer.eventRecordCallback(&query_called);

    try std.testing.expect(rig.ring.isEmpty());
    try std.testing.expect(rig.process_ring.isEmpty());
    try std.testing.expect(rig.dns_ring.isEmpty());
    try std.testing.expectEqual(@as(u32, 0), test_process_fallback_calls);
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.timeout, rig.wake.timedWait(0));
}
