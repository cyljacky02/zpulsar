//! TDH-derived fallback for unknown Kernel-Network payload versions
//! (docs/research/etw-tcp-udp-pipeline.md §3.2). The hot path parses
//! version 0 with fixed offsets (parser.zig); if a future Windows build ever
//! bumps a version, the consumer routes those events here: offsets are
//! derived once per (event id, version) from the OS manifest schema via
//! TdhGetEventInformation, cached, and reused — never a TDH call per event.
//! Events whose schema cannot be derived are dropped, not misparsed.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");
const parser = @import("parser.zig");

/// Payload offsets of the fields the Engine reads, for one (id, version).
pub const FieldOffsets = struct {
    pid: u16,
    size: u16,
    daddr: u16,
    saddr: u16,
    dport: u16,
    sport: u16,
    addr_len: u8,
    /// Bytes needed to read every field above.
    min_len: u16,
};

/// Same record construction as parser.parseV0, with schema-derived offsets.
/// Only the offsets differ: which field is the local side is decided by the
/// one shared rule, so the fallback cannot drift from the hot path (issue #36).
pub fn parseWithOffsets(
    id: u16,
    off: FieldOffsets,
    user_data: []const u8,
    timestamp_ft: i64,
) ?event.NetEvent {
    const class = parser.classify(id) orelse return null;
    if (off.addr_len != 4 and off.addr_len != 16) return null;
    if (user_data.len < off.min_len) return null;

    var out: event.NetEvent = .{
        .op = class.op,
        .proto = class.proto,
        .family = class.family,
        .icmp_type = 0,
        .pid = std.mem.readInt(u32, user_data[off.pid..][0..4], .little),
        .size = 0,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = undefined,
        .remote_port = undefined,
        .timestamp_ft = timestamp_ft,
    };
    if (class.op == .send or class.op == .recv)
        out.size = std.mem.readInt(u32, user_data[off.size..][0..4], .little);
    const addr_len: usize = off.addr_len;
    parser.assignEndpoints(&out, class.orientation(), .{
        .daddr = user_data[off.daddr..][0..addr_len],
        .saddr = user_data[off.saddr..][0..addr_len],
        .dport = std.mem.readInt(u16, user_data[off.dport..][0..2], .big),
        .sport = std.mem.readInt(u16, user_data[off.sport..][0..2], .big),
    });
    return out;
}

// ---------------------------------------------------------------------------
// Offset derivation from a TRACE_EVENT_INFO buffer. The buffer is walked at
// byte level: upstream types field positions are comptime-asserted in the
// facade, and EVENT_PROPERTY_INFO.Flags is a bitmask that zigwin32 types as a
// plain enum — loading combined bits through the enum would be checked
// illegal-value UB.
// ---------------------------------------------------------------------------

const props_off = @offsetOf(win32.TRACE_EVENT_INFO, "EventPropertyInfoArray");
const top_level_count_off = @offsetOf(win32.TRACE_EVENT_INFO, "TopLevelPropertyCount");
const prop_size = @sizeOf(win32.EVENT_PROPERTY_INFO);
const prop_flags_off = @offsetOf(win32.EVENT_PROPERTY_INFO, "Flags");
const prop_name_off = @offsetOf(win32.EVENT_PROPERTY_INFO, "NameOffset");
const prop_count_off = @offsetOf(win32.EVENT_PROPERTY_INFO, "Anonymous2");
const prop_length_off = @offsetOf(win32.EVENT_PROPERTY_INFO, "Anonymous3");

// PROPERTY_FLAGS bits that defeat flat fixed-offset accumulation.
const property_struct: u32 = 0x1;
const property_param_length: u32 = 0x2;
const property_param_count: u32 = 0x4;

const Field = enum { pid, size, daddr, saddr, dport, sport };

/// Walk the schema's top-level properties in declaration order, accumulating
/// payload offsets from their fixed lengths, until all six fields the Engine
/// reads are located. Returns null — meaning "drop these events" — if any
/// property before that point is a struct, an array, or variable-length, or
/// if a field is missing or has an unexpected width.
pub fn deriveFromTraceEventInfo(buf: []const u8) ?FieldOffsets {
    if (buf.len < props_off) return null;
    const top_level = std.mem.readInt(u32, buf[top_level_count_off..][0..4], .little);

    var offsets: std.EnumArray(Field, ?u16) = .initFill(null);
    var lengths: std.EnumArray(Field, u16) = .initFill(0);
    var offset: u32 = 0;
    var i: u32 = 0;
    while (i < top_level) : (i += 1) {
        if (allFound(offsets)) break;
        const p = props_off + i * prop_size;
        if (buf.len < p + prop_size) return null;
        const flags = std.mem.readInt(u32, buf[p + prop_flags_off ..][0..4], .little);
        if (flags & (property_struct | property_param_length | property_param_count) != 0)
            return null;
        const count = std.mem.readInt(u16, buf[p + prop_count_off ..][0..2], .little);
        if (count != 1) return null;
        const length = std.mem.readInt(u16, buf[p + prop_length_off ..][0..2], .little);
        if (length == 0) return null; // variable-length (e.g. a string)
        if (offset + length > std.math.maxInt(u16)) return null;

        const name_offset = std.mem.readInt(u32, buf[p + prop_name_off ..][0..4], .little);
        inline for (comptime std.enums.values(Field)) |field| {
            if (nameEquals(buf, name_offset, manifestName(field))) {
                offsets.set(field, @intCast(offset));
                lengths.set(field, length);
            }
        }
        offset += length;
    }
    if (!allFound(offsets)) return null;

    // Widths must be what the record layout assumes.
    if (lengths.get(.pid) != 4 or lengths.get(.size) != 4) return null;
    if (lengths.get(.dport) != 2 or lengths.get(.sport) != 2) return null;
    const addr_len = lengths.get(.daddr);
    if (addr_len != lengths.get(.saddr)) return null;
    if (addr_len != 4 and addr_len != 16) return null;

    var min_len: u16 = 0;
    inline for (comptime std.enums.values(Field)) |field| {
        min_len = @max(min_len, offsets.get(field).? + lengths.get(field));
    }
    return .{
        .pid = offsets.get(.pid).?,
        .size = offsets.get(.size).?,
        .daddr = offsets.get(.daddr).?,
        .saddr = offsets.get(.saddr).?,
        .dport = offsets.get(.dport).?,
        .sport = offsets.get(.sport).?,
        .addr_len = @intCast(addr_len),
        .min_len = min_len,
    };
}

fn allFound(offsets: std.EnumArray(Field, ?u16)) bool {
    for (std.enums.values(Field)) |f| {
        if (offsets.get(f) == null) return false;
    }
    return true;
}

/// The manifest names the fields exactly "PID", "size", "daddr", "saddr",
/// "dport", "sport" (research doc §Verdict templates).
fn manifestName(comptime field: Field) []const u8 {
    return switch (field) {
        .pid => "PID",
        .size => "size",
        .daddr => "daddr",
        .saddr => "saddr",
        .dport => "dport",
        .sport => "sport",
    };
}

fn nameEquals(buf: []const u8, name_offset: u32, comptime ascii: []const u8) bool {
    // Names are NUL-terminated UTF-16LE at offsets relative to buffer start.
    const needed = (ascii.len + 1) * 2;
    if (name_offset > buf.len or buf.len - name_offset < needed) return false;
    inline for (ascii, 0..) |c, idx| {
        const unit = std.mem.readInt(u16, buf[name_offset + 2 * idx ..][0..2], .little);
        if (unit != c) return false;
    }
    return std.mem.readInt(u16, buf[name_offset + 2 * ascii.len ..][0..2], .little) == 0;
}

// ---------------------------------------------------------------------------
// Per-(id, version) cache. `derive` is the seam: production asks TDH with the
// live EVENT_RECORD; tests inject a fake.
// ---------------------------------------------------------------------------

pub const DeriveFn = *const fn (rec: *win32.EVENT_RECORD, gpa: std.mem.Allocator) ?FieldOffsets;

pub const FallbackCache = struct {
    gpa: std.mem.Allocator,
    derive: DeriveFn = deriveViaTdh,
    /// null entry = derivation failed once; keep dropping without re-asking.
    map: std.AutoHashMapUnmanaged(u32, ?FieldOffsets) = .empty,

    pub fn init(gpa: std.mem.Allocator) FallbackCache {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *FallbackCache) void {
        self.map.deinit(self.gpa);
    }

    fn cacheKey(id: u16, version: u8) u32 {
        return (@as(u32, id) << 8) | version;
    }

    pub fn parse(
        self: *FallbackCache,
        rec: *win32.EVENT_RECORD,
        user_data: []const u8,
        timestamp_ft: i64,
    ) ?event.NetEvent {
        const id = rec.EventHeader.EventDescriptor.Id;
        const version = rec.EventHeader.EventDescriptor.Version;
        // OOM: drop the event rather than fail the consumer thread.
        const gop = self.map.getOrPut(self.gpa, cacheKey(id, version)) catch return null;
        if (!gop.found_existing) gop.value_ptr.* = self.derive(rec, self.gpa);
        const off = gop.value_ptr.* orelse return null;
        return parseWithOffsets(id, off, user_data, timestamp_ft);
    }
};

/// Production derivation: ask TDH for the event's manifest schema (registered
/// OS-wide for this provider) and walk it. Any failure means "drop".
fn deriveViaTdh(rec: *win32.EVENT_RECORD, gpa: std.mem.Allocator) ?FieldOffsets {
    var size: u32 = 0;
    var rc = win32.TdhGetEventInformation(rec, 0, null, null, &size);
    if (rc != win32.ERROR_INSUFFICIENT_BUFFER) return null;
    const buf = gpa.alignedAlloc(u8, .of(win32.TRACE_EVENT_INFO), size) catch return null;
    defer gpa.free(buf);
    rc = win32.TdhGetEventInformation(rec, 0, null, @ptrCast(buf.ptr), &size);
    if (rc != win32.ERROR_SUCCESS) return null;
    return deriveFromTraceEventInfo(buf[0..size]);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TestProp = struct {
    name: []const u8,
    len: u16,
    flags: u32 = 0,
    count: u16 = 1,
};

/// Build a synthetic TRACE_EVENT_INFO buffer: zeroed header with the counts
/// set, the property array, then the UTF-16 name table.
fn buildInfoBuffer(gpa: std.mem.Allocator, props: []const TestProp) ![]u8 {
    var names_len: usize = 0;
    for (props) |p| names_len += (p.name.len + 1) * 2;
    const names_base = props_off + props.len * prop_size;
    const buf = try gpa.alloc(u8, names_base + names_len);
    @memset(buf, 0);
    std.mem.writeInt(u32, buf[@offsetOf(win32.TRACE_EVENT_INFO, "PropertyCount")..][0..4], @intCast(props.len), .little);
    std.mem.writeInt(u32, buf[top_level_count_off..][0..4], @intCast(props.len), .little);
    var name_cursor = names_base;
    for (props, 0..) |p, i| {
        const at = props_off + i * prop_size;
        std.mem.writeInt(u32, buf[at + prop_flags_off ..][0..4], p.flags, .little);
        std.mem.writeInt(u32, buf[at + prop_name_off ..][0..4], @intCast(name_cursor), .little);
        std.mem.writeInt(u16, buf[at + prop_count_off ..][0..2], p.count, .little);
        std.mem.writeInt(u16, buf[at + prop_length_off ..][0..2], p.len, .little);
        for (p.name) |c| {
            std.mem.writeInt(u16, buf[name_cursor..][0..2], c, .little);
            name_cursor += 2;
        }
        std.mem.writeInt(u16, buf[name_cursor..][0..2], 0, .little);
        name_cursor += 2;
    }
    return buf;
}

const v0_shape_v4 = [_]TestProp{
    .{ .name = "PID", .len = 4 },     .{ .name = "size", .len = 4 },
    .{ .name = "daddr", .len = 4 },   .{ .name = "saddr", .len = 4 },
    .{ .name = "dport", .len = 2 },   .{ .name = "sport", .len = 2 },
    .{ .name = "seqnum", .len = 4 },  .{ .name = "connid", .len = 4 },
};

test "derivation reproduces the v4 fixed offsets from a schema" {
    const buf = try buildInfoBuffer(std.testing.allocator, &v0_shape_v4);
    defer std.testing.allocator.free(buf);
    const off = deriveFromTraceEventInfo(buf) orelse return error.DeriveFailed;
    try std.testing.expectEqual(test_v4_offsets, off);
}

test "derivation follows inserted fields in a hypothetical future version" {
    // A future build inserts a u64 before PID and widens nothing else: every
    // fixed offset the v0 parser assumes is now wrong, the derived ones move.
    const shifted = [_]TestProp{
        .{ .name = "flags", .len = 8 },
        .{ .name = "PID", .len = 4 },   .{ .name = "size", .len = 4 },
        .{ .name = "daddr", .len = 16 }, .{ .name = "saddr", .len = 16 },
        .{ .name = "dport", .len = 2 }, .{ .name = "sport", .len = 2 },
    };
    const buf = try buildInfoBuffer(std.testing.allocator, &shifted);
    defer std.testing.allocator.free(buf);
    const off = deriveFromTraceEventInfo(buf) orelse return error.DeriveFailed;
    try std.testing.expectEqual(FieldOffsets{
        .pid = 8, .size = 12, .daddr = 16, .saddr = 32, .dport = 48, .sport = 50,
        .addr_len = 16, .min_len = 52,
    }, off);

    // And parsing with those offsets attributes correctly.
    var payload: [52]u8 = @splat(0);
    std.mem.writeInt(u32, payload[8..12], 4242, .little); // PID
    std.mem.writeInt(u32, payload[12..16], 999, .little); // size
    std.mem.writeInt(u16, payload[48..50], 443, .big); // dport
    std.mem.writeInt(u16, payload[50..52], 51000, .big); // sport
    const ev = parseWithOffsets(parser.Id.tcp6_send, off, &payload, 5) orelse
        return error.ParseFailed;
    try std.testing.expectEqual(@as(u32, 4242), ev.pid);
    try std.testing.expectEqual(@as(u32, 999), ev.size);
    try std.testing.expectEqual(@as(u16, 443), ev.remote_port);
    try std.testing.expectEqual(@as(u16, 51000), ev.local_port);
    try std.testing.expectEqual(event.Family.v6, ev.family);
}

test "the fallback orients per (id, direction), exactly as the hot path does" {
    // The payload issue #36 reported: a DNS answer arriving from 8.8.8.8:53
    // at this machine's 192.168.88.254:60253. saddr is the sender.
    var payload: [20]u8 = @splat(0);
    std.mem.writeInt(u32, payload[0..4], 4242, .little); // PID
    std.mem.writeInt(u32, payload[4..8], 51, .little); // size
    @memcpy(payload[8..12], &[4]u8{ 192, 168, 88, 254 }); // daddr — the receiver
    @memcpy(payload[12..16], &[4]u8{ 8, 8, 8, 8 }); // saddr — the sender
    std.mem.writeInt(u16, payload[16..18], 60253, .big); // dport
    std.mem.writeInt(u16, payload[18..20], 53, .big); // sport

    const udp = parseWithOffsets(parser.Id.udp4_recv, test_v4_offsets, &payload, 9) orelse
        return error.ParseFailed;
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 88, 254 }, udp.local_addr[0..4]);
    try std.testing.expectEqual(@as(u16, 60253), udp.local_port);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 8, 8, 8, 8 }, udp.remote_addr[0..4]);
    try std.testing.expectEqual(@as(u16, 53), udp.remote_port);
    // Derived offsets change where the fields are, never which one is local:
    // on a v0 payload the two paths must produce the identical record.
    try std.testing.expectEqual(
        parser.parseV0(parser.Id.udp4_recv, &payload, 9),
        @as(?event.NetEvent, udp),
    );

    // The same bytes read as TCP recv stay endpoint-oriented.
    const tcp = parseWithOffsets(parser.Id.tcp4_recv, test_v4_offsets, &payload, 9) orelse
        return error.ParseFailed;
    try std.testing.expectEqualSlices(u8, &[4]u8{ 8, 8, 8, 8 }, tcp.local_addr[0..4]);
    try std.testing.expectEqual(@as(u16, 53), tcp.local_port);
}

test "derivation refuses schemas it cannot walk" {
    const cases = [_][]const TestProp{
        // Missing PID entirely.
        &.{ .{ .name = "size", .len = 4 }, .{ .name = "daddr", .len = 4 } },
        // Variable-length property before the fields we need.
        &.{ .{ .name = "junk", .len = 0 }, .{ .name = "PID", .len = 4 } },
        // Length driven by another property.
        &.{ .{ .name = "junk", .len = 4, .flags = property_param_length }, .{ .name = "PID", .len = 4 } },
        // A struct property.
        &.{ .{ .name = "junk", .len = 4, .flags = property_struct }, .{ .name = "PID", .len = 4 } },
        // An array.
        &.{ .{ .name = "junk", .len = 4, .count = 3 }, .{ .name = "PID", .len = 4 } },
        // Unexpected widths.
        &.{
            .{ .name = "PID", .len = 8 },   .{ .name = "size", .len = 4 },
            .{ .name = "daddr", .len = 4 }, .{ .name = "saddr", .len = 4 },
            .{ .name = "dport", .len = 2 }, .{ .name = "sport", .len = 2 },
        },
    };
    for (cases) |props| {
        const buf = try buildInfoBuffer(std.testing.allocator, props);
        defer std.testing.allocator.free(buf);
        try std.testing.expectEqual(@as(?FieldOffsets, null), deriveFromTraceEventInfo(buf));
    }
}

test "variable-length fields after ours don't block derivation" {
    const props = v0_shape_v4 ++ [_]TestProp{.{ .name = "trailingString", .len = 0 }};
    const buf = try buildInfoBuffer(std.testing.allocator, &props);
    defer std.testing.allocator.free(buf);
    try std.testing.expect(deriveFromTraceEventInfo(buf) != null);
}

/// The v0 v4 layout as FieldOffsets — what parser.parseV0 hardcodes; shared
/// by fallback tests here and in consumer.zig.
pub const test_v4_offsets: FieldOffsets = .{
    .pid = 0,
    .size = 4,
    .daddr = 8,
    .saddr = 12,
    .dport = 16,
    .sport = 18,
    .addr_len = 4,
    .min_len = 20,
};

var test_derive_calls: u32 = 0;

fn testDerive(rec: *win32.EVENT_RECORD, gpa: std.mem.Allocator) ?FieldOffsets {
    _ = rec;
    _ = gpa;
    test_derive_calls += 1;
    return test_v4_offsets;
}

fn testFailDerive(rec: *win32.EVENT_RECORD, gpa: std.mem.Allocator) ?FieldOffsets {
    _ = rec;
    _ = gpa;
    test_derive_calls += 1;
    return null;
}

fn testRecord(id: u16, version: u8) win32.EVENT_RECORD {
    var rec = std.mem.zeroes(win32.EVENT_RECORD);
    rec.EventHeader.EventDescriptor.Id = id;
    rec.EventHeader.EventDescriptor.Version = version;
    return rec;
}

test "fallback cache derives once per (id, version) and parses through it" {
    var cache = FallbackCache.init(std.testing.allocator);
    defer cache.deinit();
    cache.derive = &testDerive;
    test_derive_calls = 0;

    var rec = testRecord(parser.Id.tcp4_recv, 1);
    var payload: [20]u8 = @splat(0);
    std.mem.writeInt(u32, payload[0..4], 777, .little);
    std.mem.writeInt(u32, payload[4..8], 123, .little);

    const first = cache.parse(&rec, &payload, 0) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u32, 777), first.pid);
    try std.testing.expectEqual(@as(u32, 123), first.size);
    try std.testing.expectEqual(event.Op.recv, first.op);
    _ = cache.parse(&rec, &payload, 0) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u32, 1), test_derive_calls);

    // A different version derives separately.
    var rec_v2 = testRecord(parser.Id.tcp4_recv, 2);
    _ = cache.parse(&rec_v2, &payload, 0) orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u32, 2), test_derive_calls);
}

test "failed derivation is cached: events drop without re-asking TDH" {
    var cache = FallbackCache.init(std.testing.allocator);
    defer cache.deinit();
    cache.derive = &testFailDerive;
    test_derive_calls = 0;

    var rec = testRecord(parser.Id.tcp4_recv, 7);
    var payload: [20]u8 = @splat(0);
    try std.testing.expectEqual(@as(?event.NetEvent, null), cache.parse(&rec, &payload, 0));
    try std.testing.expectEqual(@as(?event.NetEvent, null), cache.parse(&rec, &payload, 0));
    try std.testing.expectEqual(@as(u32, 1), test_derive_calls);
}
