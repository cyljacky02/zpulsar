//! Fixed-offset parsing of Microsoft-Windows-Kernel-Network payloads into
//! NetEvent records (docs/research/etw-tcp-udp-pipeline.md §Verdict, §3.2).
//! Runs on the ETW consumer thread's hot path: a switch on the event id, a
//! bounds check, and direct loads — no TDH. This path is version-0 only; the
//! consumer routes unknown versions to the TDH-derived fallback (tdh.zig).
//!
//! The attribution key is the payload PID, never the header PID (§2.3).
//! Retransmit (14/30) and protocol-copy (18/34) events are recognized and
//! excluded — they never become records, so they provably cannot reach the
//! In-session Totals.

const std = @import("std");
const event = @import("event.zig");

pub const NetEvent = event.NetEvent;

/// Kernel-Network event ids (provider manifest; same mapping as
/// TraceEvent's KernelTraceEventParser).
pub const Id = struct {
    pub const tcp4_send: u16 = 10;
    pub const tcp4_recv: u16 = 11;
    pub const tcp4_connect: u16 = 12;
    pub const tcp4_disconnect: u16 = 13;
    pub const tcp4_retransmit: u16 = 14;
    pub const tcp4_accept: u16 = 15;
    pub const tcp4_reconnect: u16 = 16;
    pub const tcp_connect_fail: u16 = 17;
    pub const tcp4_copy: u16 = 18;
    pub const tcp6_send: u16 = 26;
    pub const tcp6_recv: u16 = 27;
    pub const tcp6_connect: u16 = 28;
    pub const tcp6_disconnect: u16 = 29;
    pub const tcp6_retransmit: u16 = 30;
    pub const tcp6_accept: u16 = 31;
    pub const tcp6_reconnect: u16 = 32;
    pub const tcp6_copy: u16 = 34;
    pub const udp4_send: u16 = 42;
    pub const udp4_recv: u16 = 43;
    pub const udp_send_fail: u16 = 49;
    pub const udp6_send: u16 = 58;
    pub const udp6_recv: u16 = 59;
};

/// What an event id means for the Engine. Retransmit/copy/reconnect/fail ids
/// deliberately classify to null alongside unknown ids: nothing downstream
/// may ever account them.
pub fn classify(id: u16) ?struct { op: event.Op, proto: event.Proto, family: event.Family } {
    return switch (id) {
        Id.tcp4_send => .{ .op = .send, .proto = .tcp, .family = .v4 },
        Id.tcp4_recv => .{ .op = .recv, .proto = .tcp, .family = .v4 },
        Id.tcp4_connect, Id.tcp4_accept => .{ .op = .connect, .proto = .tcp, .family = .v4 },
        Id.tcp4_disconnect => .{ .op = .disconnect, .proto = .tcp, .family = .v4 },
        Id.tcp6_send => .{ .op = .send, .proto = .tcp, .family = .v6 },
        Id.tcp6_recv => .{ .op = .recv, .proto = .tcp, .family = .v6 },
        Id.tcp6_connect, Id.tcp6_accept => .{ .op = .connect, .proto = .tcp, .family = .v6 },
        Id.tcp6_disconnect => .{ .op = .disconnect, .proto = .tcp, .family = .v6 },
        Id.udp4_send => .{ .op = .send, .proto = .udp, .family = .v4 },
        Id.udp4_recv => .{ .op = .recv, .proto = .udp, .family = .v4 },
        Id.udp6_send => .{ .op = .send, .proto = .udp, .family = .v6 },
        Id.udp6_recv => .{ .op = .recv, .proto = .udp, .family = .v6 },
        else => null,
    };
}

/// Version-0 payload layout, common prefix of every event this provider
/// emits: PID:u32, size:u32, daddr, saddr, dport:u16, sport:u16, …
/// (docs/research/etw-tcp-udp-pipeline.md §Verdict). Addresses and ports are
/// network byte order; ports are converted to host order here, once.
///
/// Orientation: saddr/sport are the local side and daddr/dport the remote
/// side for every event — the fields describe the endpoint pair, not the
/// packet. Verified live (issue #20): a two-process echo pair seeded from the
/// tables kept exact connection counts under bidirectional traffic; a
/// packet-oriented recv layout would have inserted phantom connections.
pub fn parseV0(id: u16, user_data: []const u8, timestamp_ft: i64) ?NetEvent {
    const class = classify(id) orelse return null;

    var out: NetEvent = .{
        .op = class.op,
        .proto = class.proto,
        .family = class.family,
        .pid = undefined,
        .size = undefined,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = undefined,
        .remote_port = undefined,
        .timestamp_ft = timestamp_ft,
    };

    const addr_len: usize = switch (class.family) {
        .v4 => 4,
        .v6 => 16,
    };
    const dport_off = 8 + 2 * addr_len;
    if (user_data.len < dport_off + 4) return null;

    out.pid = std.mem.readInt(u32, user_data[0..4], .little);
    // Lifecycle events reuse the size slot for other meanings (e.g. the
    // connect-failed error code); only data events may carry bytes.
    out.size = switch (class.op) {
        .send, .recv => std.mem.readInt(u32, user_data[4..8], .little),
        .connect, .disconnect => 0,
    };
    @memcpy(out.remote_addr[0..addr_len], user_data[8..][0..addr_len]);
    @memcpy(out.local_addr[0..addr_len], user_data[8 + addr_len ..][0..addr_len]);
    out.remote_port = std.mem.readInt(u16, user_data[dport_off..][0..2], .big);
    out.local_port = std.mem.readInt(u16, user_data[dport_off + 2 ..][0..2], .big);
    return out;
}

// ---------------------------------------------------------------------------
// Fixtures — every (event id, version 0) layout the engine claims to parse,
// built field-by-field in the documented order (spec issue #18, Testing
// Decisions). The builders ARE the layout: change an offset and the payload
// bytes change with it.
// ---------------------------------------------------------------------------

fn le32(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    return b;
}

fn be16(v: u16) [2]u8 {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    return b;
}

const test_pid: u32 = 0x0000abcd;
const test_size: u32 = 1500;
const remote4 = [4]u8{ 93, 184, 216, 34 }; // daddr
const local4 = [4]u8{ 192, 168, 1, 2 }; // saddr
const remote6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
const local6 = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };
const remote_port: u16 = 443;
const local_port: u16 = 51000;

/// PID, size, daddr, saddr, dport, sport (+ per-id trailer the parser skips).
/// Call at comptime only — a runtime call would return a pointer to a dead
/// stack temporary.
fn v4Payload(comptime trailer: []const u8) []const u8 {
    return &(le32(test_pid) ++ le32(test_size) ++ remote4 ++ local4 ++
        be16(remote_port) ++ be16(local_port) ++ trailer[0..trailer.len].*);
}

fn v6Payload(comptime trailer: []const u8) []const u8 {
    return &(le32(test_pid) ++ le32(test_size) ++ remote6 ++ local6 ++
        be16(remote_port) ++ be16(local_port) ++ trailer[0..trailer.len].*);
}

// Trailers per the manifest templates (parser must skip them, so fixtures
// carry the real full length).
const seq_conn = le32(0x1111) ++ le32(0x2222); // seqnum, connid
const send_trailer = le32(1) ++ le32(2) ++ seq_conn; // startime, endtime, seqnum, connid
// mss, sackopt, tsopt, wsopt, rcvwin, rcvwinscale, sndwinscale, seqnum, connid
const connect_trailer = be16(1460) ++ be16(1) ++ be16(0) ++ be16(1) ++
    le32(65535) ++ be16(8) ++ be16(7) ++ seq_conn;

const Expect = struct {
    op: event.Op,
    proto: event.Proto,
    family: event.Family,
    size: u32,
};

const Fixture = struct {
    name: []const u8,
    id: u16,
    payload: []const u8,
    expect: ?Expect,
};

const fixtures = [_]Fixture{
    // Data events: size accumulates into In-session Totals.
    .{ .name = "10 TCPv4 send", .id = 10, .payload = v4Payload(&send_trailer), .expect = .{ .op = .send, .proto = .tcp, .family = .v4, .size = test_size } },
    .{ .name = "11 TCPv4 recv", .id = 11, .payload = v4Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .tcp, .family = .v4, .size = test_size } },
    .{ .name = "26 TCPv6 send", .id = 26, .payload = v6Payload(&send_trailer), .expect = .{ .op = .send, .proto = .tcp, .family = .v6, .size = test_size } },
    .{ .name = "27 TCPv6 recv", .id = 27, .payload = v6Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .tcp, .family = .v6, .size = test_size } },
    .{ .name = "42 UDPv4 send", .id = 42, .payload = v4Payload(&seq_conn), .expect = .{ .op = .send, .proto = .udp, .family = .v4, .size = test_size } },
    .{ .name = "43 UDPv4 recv", .id = 43, .payload = v4Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .udp, .family = .v4, .size = test_size } },
    .{ .name = "58 UDPv6 send", .id = 58, .payload = v6Payload(&seq_conn), .expect = .{ .op = .send, .proto = .udp, .family = .v6, .size = test_size } },
    .{ .name = "59 UDPv6 recv", .id = 59, .payload = v6Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .udp, .family = .v6, .size = test_size } },
    // Lifecycle events: maintain the connection list, never carry bytes.
    .{ .name = "12 TCPv4 connect", .id = 12, .payload = v4Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v4, .size = 0 } },
    .{ .name = "15 TCPv4 accept", .id = 15, .payload = v4Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v4, .size = 0 } },
    .{ .name = "13 TCPv4 disconnect", .id = 13, .payload = v4Payload(&seq_conn), .expect = .{ .op = .disconnect, .proto = .tcp, .family = .v4, .size = 0 } },
    .{ .name = "28 TCPv6 connect", .id = 28, .payload = v6Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v6, .size = 0 } },
    .{ .name = "31 TCPv6 accept", .id = 31, .payload = v6Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v6, .size = 0 } },
    .{ .name = "29 TCPv6 disconnect", .id = 29, .payload = v6Payload(&seq_conn), .expect = .{ .op = .disconnect, .proto = .tcp, .family = .v6, .size = 0 } },
    // Excluded from totals (spec issue #18): retransmit bytes were already
    // counted at send; protocol copy would double count. A valid payload
    // must still parse to nothing.
    .{ .name = "14 TCPv4 retransmit excluded", .id = 14, .payload = v4Payload(&seq_conn), .expect = null },
    .{ .name = "30 TCPv6 retransmit excluded", .id = 30, .payload = v6Payload(&seq_conn), .expect = null },
    .{ .name = "18 TCPv4 protocol copy excluded", .id = 18, .payload = v4Payload(&seq_conn), .expect = null },
    .{ .name = "34 TCPv6 protocol copy excluded", .id = 34, .payload = v6Payload(&seq_conn), .expect = null },
    // Ignored: reconnect carries no bytes; fail events have a different
    // payload (error code in the size slot — must never be read as bytes).
    .{ .name = "16 TCPv4 reconnect ignored", .id = 16, .payload = v4Payload(&seq_conn), .expect = null },
    .{ .name = "32 TCPv6 reconnect ignored", .id = 32, .payload = v6Payload(&seq_conn), .expect = null },
    .{ .name = "17 TCP connect-fail ignored", .id = 17, .payload = v4Payload(&seq_conn), .expect = null },
    .{ .name = "49 UDP send-fail ignored", .id = 49, .payload = v4Payload(&seq_conn), .expect = null },
    .{ .name = "unknown id ignored", .id = 999, .payload = v4Payload(&seq_conn), .expect = null },
};

test "fixtures: every (id, v0) layout parses to its classification or to nothing" {
    for (fixtures) |f| {
        errdefer std.debug.print("fixture failed: {s}\n", .{f.name});
        const parsed = parseV0(f.id, f.payload, 777);
        if (f.expect) |exp| {
            const ev = parsed orelse return error.ExpectedRecord;
            try std.testing.expectEqual(exp.op, ev.op);
            try std.testing.expectEqual(exp.proto, ev.proto);
            try std.testing.expectEqual(exp.family, ev.family);
            try std.testing.expectEqual(exp.size, ev.size);
            try std.testing.expectEqual(test_pid, ev.pid);
            try std.testing.expectEqual(@as(i64, 777), ev.timestamp_ft);
            // Ports come out in host order; addresses stay raw network bytes.
            try std.testing.expectEqual(remote_port, ev.remote_port);
            try std.testing.expectEqual(local_port, ev.local_port);
            switch (exp.family) {
                .v4 => {
                    try std.testing.expectEqualSlices(u8, &remote4, ev.remote_addr[0..4]);
                    try std.testing.expectEqualSlices(u8, &local4, ev.local_addr[0..4]);
                    try std.testing.expectEqualSlices(u8, &(@as([12]u8, @splat(0))), ev.remote_addr[4..]);
                },
                .v6 => {
                    try std.testing.expectEqualSlices(u8, &remote6, &ev.remote_addr);
                    try std.testing.expectEqualSlices(u8, &local6, &ev.local_addr);
                },
            }
        } else {
            try std.testing.expectEqual(@as(?NetEvent, null), parsed);
        }
    }
}

test "truncated payloads parse to nothing" {
    const v4 = comptime v4Payload(&seq_conn);
    const v6 = comptime v6Payload(&seq_conn);
    // One byte short of the last field the parser reads (sport end).
    try std.testing.expectEqual(@as(?NetEvent, null), parseV0(10, v4[0..19], 0));
    try std.testing.expectEqual(@as(?NetEvent, null), parseV0(27, v6[0..43], 0));
    try std.testing.expectEqual(@as(?NetEvent, null), parseV0(42, &.{}, 0));
    // Exactly the read prefix (trailer absent) still parses.
    try std.testing.expect(parseV0(11, v4[0..20], 0) != null);
    try std.testing.expect(parseV0(27, v6[0..44], 0) != null);
}
