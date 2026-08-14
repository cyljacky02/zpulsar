//! The ETW consumer thread (ADR-0002 thread 2): blocked in ProcessTrace on
//! the `zPulsarNet` real-time session, parse-only — every Kernel-Network
//! event becomes a fixed-size record pushed onto the SPSC ring, or nothing.
//! Version 0 payloads take the fixed-offset hot path; unknown versions route
//! to the TDH-derived fallback. The wake event is set exactly on the ring's
//! empty→non-empty transition.

const std = @import("std");
const win32 = @import("win32");
const etw_session = @import("etw_session.zig");
const event = @import("event.zig");
const parser = @import("parser.zig");
const spsc_ring = @import("spsc_ring.zig");
const sync = @import("sync.zig");
const tdh = @import("tdh.zig");

/// Spec issue #18: power-of-two 16 Ki × ~64 B records (~1 MiB, heap).
pub const ring_capacity = 16 * 1024;
pub const Ring = spsc_ring.SpscRing(event.NetEvent, ring_capacity);

pub const Consumer = struct {
    ring: *Ring,
    wake: sync.WakeEvent,
    fallback: tdh.FallbackCache,
    trace: win32.PROCESSTRACE_HANDLE = win32.INVALID_PROCESSTRACE_HANDLE,
    /// OpenTraceW may write into the logfile struct; the name buffer must
    /// outlive the ProcessTrace call.
    name_buf: [etw_session.session_name_w.len:0]u16 = etw_session.session_name_w.*,

    pub fn init(ring: *Ring, wake: sync.WakeEvent, gpa: std.mem.Allocator) Consumer {
        return .{ .ring = ring, .wake = wake, .fallback = .init(gpa) };
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

    /// The whole per-event hot path. The attribution PID comes from the
    /// payload inside parse — the header PID is never read (research §2.3).
    fn handleRecord(self: *Consumer, rec: *win32.EVENT_RECORD) void {
        const hdr = &rec.EventHeader;
        // The session also delivers ETW's own control events (e.g. the
        // EventTrace header); only Kernel-Network is ours.
        if (!std.mem.eql(u8, &hdr.ProviderId.Bytes, &etw_session.kernel_network_guid.Bytes))
            return;
        const user_data: []const u8 = if (rec.UserData) |p|
            @as([*]const u8, @ptrCast(p))[0..rec.UserDataLength]
        else
            &.{};
        const ts = hdr.TimeStamp.QuadPart;
        const desc = hdr.EventDescriptor;
        const parsed = if (desc.Version == 0)
            parser.parseV0(desc.Id, user_data, ts)
        else
            self.fallback.parse(rec, user_data, ts);
        const ev = parsed orelse return;
        if (self.ring.push(ev) == .pushed_was_empty) self.wake.set();
    }
};

// ---------------------------------------------------------------------------
// Tests — dispatch only; the live ProcessTrace path needs elevation and runs
// through the headless rig.
// ---------------------------------------------------------------------------

fn testRecord(id: u16, version: u8, payload: []const u8, self: *Consumer) win32.EVENT_RECORD {
    var rec = std.mem.zeroes(win32.EVENT_RECORD);
    rec.EventHeader.ProviderId = etw_session.kernel_network_guid;
    rec.EventHeader.EventDescriptor.Id = id;
    rec.EventHeader.EventDescriptor.Version = version;
    rec.EventHeader.TimeStamp.QuadPart = 12345;
    rec.UserData = @constCast(@ptrCast(payload.ptr));
    rec.UserDataLength = @intCast(payload.len);
    rec.UserContext = self;
    return rec;
}

/// A valid v0 TCPv4-recv payload: PID, size, daddr, saddr, dport, sport.
const test_payload = blk: {
    var b: [20]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], 4242, .little);
    std.mem.writeInt(u32, b[4..8], 100, .little);
    std.mem.writeInt(u16, b[16..18], 443, .big);
    std.mem.writeInt(u16, b[18..20], 51000, .big);
    break :blk b;
};

var test_fallback_calls: u32 = 0;

fn testFallbackDerive(rec: *win32.EVENT_RECORD, gpa: std.mem.Allocator) ?tdh.FieldOffsets {
    _ = rec;
    _ = gpa;
    test_fallback_calls += 1;
    return tdh.test_v4_offsets;
}

test "version 0 takes the fixed-offset path and lands on the ring" {
    const ring = try std.testing.allocator.create(Ring);
    defer std.testing.allocator.destroy(ring);
    ring.* = .{};
    const wake = try sync.WakeEvent.init();
    defer wake.deinit();
    var consumer = Consumer.init(ring, wake, std.testing.allocator);
    defer consumer.deinit();
    consumer.fallback.derive = &testFallbackDerive;
    test_fallback_calls = 0;

    var rec = testRecord(parser.Id.tcp4_recv, 0, &test_payload, &consumer);
    Consumer.eventRecordCallback(&rec);

    try std.testing.expectEqual(@as(u32, 0), test_fallback_calls);
    const ev = ring.pop() orelse return error.NothingPushed;
    try std.testing.expectEqual(@as(u32, 4242), ev.pid);
    try std.testing.expectEqual(@as(u32, 100), ev.size);
    try std.testing.expectEqual(@as(i64, 12345), ev.timestamp_qpc);
    // Empty→non-empty push must have set the wake event.
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, wake.timedWait(0));
}

test "unknown versions route to the TDH-derived fallback" {
    const ring = try std.testing.allocator.create(Ring);
    defer std.testing.allocator.destroy(ring);
    ring.* = .{};
    const wake = try sync.WakeEvent.init();
    defer wake.deinit();
    var consumer = Consumer.init(ring, wake, std.testing.allocator);
    defer consumer.deinit();
    consumer.fallback.derive = &testFallbackDerive;
    test_fallback_calls = 0;

    var rec = testRecord(parser.Id.tcp4_recv, 1, &test_payload, &consumer);
    Consumer.eventRecordCallback(&rec);
    Consumer.eventRecordCallback(&rec);

    try std.testing.expectEqual(@as(u32, 1), test_fallback_calls); // derived once
    try std.testing.expectEqual(@as(u32, 4242), ring.pop().?.pid);
    try std.testing.expectEqual(@as(u32, 4242), ring.pop().?.pid);
}

test "foreign providers and excluded events never reach the ring" {
    const ring = try std.testing.allocator.create(Ring);
    defer std.testing.allocator.destroy(ring);
    ring.* = .{};
    const wake = try sync.WakeEvent.init();
    defer wake.deinit();
    var consumer = Consumer.init(ring, wake, std.testing.allocator);
    defer consumer.deinit();

    var foreign = testRecord(parser.Id.tcp4_recv, 0, &test_payload, &consumer);
    foreign.EventHeader.ProviderId = win32.Guid.initString("00000000-0000-0000-0000-000000000001");
    Consumer.eventRecordCallback(&foreign);

    var retransmit = testRecord(parser.Id.tcp4_retransmit, 0, &test_payload, &consumer);
    Consumer.eventRecordCallback(&retransmit);

    try std.testing.expect(ring.isEmpty());
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.timeout, wake.timedWait(0));
}
