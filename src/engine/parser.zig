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

/// Which endpoint the payload's saddr/sport describe. Decided per (event id,
/// direction) — see `Class.orientation`.
pub const Orientation = enum {
    /// saddr/sport are the local side and daddr/dport the remote side: the
    /// fields describe the endpoint pair, whichever way the bytes moved.
    endpoint,
    /// saddr/sport are the datagram's sender and daddr/dport its destination,
    /// so the *local* side is daddr/dport.
    datagram,
};

/// What an event id means for the Engine.
pub const Class = struct {
    op: event.Op,
    proto: event.Proto,
    family: event.Family,

    /// TCP is logged against the connection, so saddr is the local side in
    /// both directions. UDP has no connection: the receive path logs the
    /// datagram itself, so saddr is whoever sent it — the remote (issue #36).
    ///
    /// Measured per (id, direction) on both families, over the wire and over
    /// loopback (docs/research/etw-tcp-udp-pipeline.md §2.5). The provider
    /// manifest cannot settle this — its message text is packet-phrased
    /// ("from %4:%6 to %3:%5") for every id, TCP recv included, where it is
    /// demonstrably wrong.
    pub fn orientation(self: Class) Orientation {
        return if (self.proto == .udp and self.op == .recv) .datagram else .endpoint;
    }
};

/// The payload's four endpoint fields, exactly as the manifest names them and
/// before anything has decided which side is which. Named rather than
/// positional on purpose: two `[]const u8` then two `u16` is an argument list
/// you can transpose silently, and transposing them is precisely issue #36.
pub const RawEndpoints = struct {
    daddr: []const u8,
    saddr: []const u8,
    dport: u16,
    sport: u16,
};

/// Write one record's endpoints from the payload's raw fields. Shared by the
/// fixed-offset hot path and the TDH-derived fallback so the two can never
/// disagree about which field is the local side.
pub fn assignEndpoints(out: *NetEvent, orient: Orientation, raw: RawEndpoints) void {
    switch (orient) {
        .endpoint => {
            @memcpy(out.local_addr[0..raw.saddr.len], raw.saddr);
            @memcpy(out.remote_addr[0..raw.daddr.len], raw.daddr);
            out.local_port = raw.sport;
            out.remote_port = raw.dport;
        },
        .datagram => {
            @memcpy(out.local_addr[0..raw.daddr.len], raw.daddr);
            @memcpy(out.remote_addr[0..raw.saddr.len], raw.saddr);
            out.local_port = raw.dport;
            out.remote_port = raw.sport;
        },
    }
}

/// Retransmit/copy/reconnect/fail ids deliberately classify to null alongside
/// unknown ids: nothing downstream may ever account them.
pub fn classify(id: u16) ?Class {
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
/// Which of daddr/saddr is the local side is not global — it is per (event
/// id, direction). See `Class.orientation`.
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
    assignEndpoints(&out, class.orientation(), .{
        .daddr = user_data[8..][0..addr_len],
        .saddr = user_data[8 + addr_len ..][0..addr_len],
        .dport = std.mem.readInt(u16, user_data[dport_off..][0..2], .big),
        .sport = std.mem.readInt(u16, user_data[dport_off + 2 ..][0..2], .big),
    });
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
// The payload's own fields, named as the manifest names them. Which of the two
// is the local side is exactly what the parser has to decide, so the fixtures
// must not prejudge it by calling them "local" and "remote".
const daddr4 = [4]u8{ 93, 184, 216, 34 };
const saddr4 = [4]u8{ 192, 168, 1, 2 };
const daddr6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
const saddr6 = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };
const test_dport: u16 = 443;
const test_sport: u16 = 51000;

// PID, size, daddr, saddr, dport, sport (+ per-id trailer the parser skips).
// The *Of builders take the address/port fields explicitly, so a test can lay
// out a datagram travelling either way. Call at comptime only — a runtime call
// would return a pointer to a dead stack temporary.

fn v4PayloadOf(
    comptime d: [4]u8,
    comptime s: [4]u8,
    comptime dp: u16,
    comptime sp: u16,
    comptime trailer: []const u8,
) []const u8 {
    return &(le32(test_pid) ++ le32(test_size) ++ d ++ s ++
        be16(dp) ++ be16(sp) ++ trailer[0..trailer.len].*);
}

fn v6PayloadOf(
    comptime d: [16]u8,
    comptime s: [16]u8,
    comptime dp: u16,
    comptime sp: u16,
    comptime trailer: []const u8,
) []const u8 {
    return &(le32(test_pid) ++ le32(test_size) ++ d ++ s ++
        be16(dp) ++ be16(sp) ++ trailer[0..trailer.len].*);
}

fn v4Payload(comptime trailer: []const u8) []const u8 {
    return v4PayloadOf(daddr4, saddr4, test_dport, test_sport, trailer);
}

fn v6Payload(comptime trailer: []const u8) []const u8 {
    return v6PayloadOf(daddr6, saddr6, test_dport, test_sport, trailer);
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
    /// Which payload field this id's local endpoint comes from — stated per
    /// fixture as measured ground truth (research §2.5), never derived the way
    /// the parser derives it, so the two have to agree.
    orient: Orientation,
};

const Fixture = struct {
    name: []const u8,
    id: u16,
    payload: []const u8,
    expect: ?Expect,
};

const fixtures = [_]Fixture{
    // Data events: size accumulates into In-session Totals. Every TCP id is
    // endpoint-oriented in *both* directions — the payload describes the
    // connection — while a UDP recv describes the arriving datagram, so its
    // local side is daddr/dport (research §2.5, issue #36).
    .{ .name = "10 TCPv4 send", .id = 10, .payload = v4Payload(&send_trailer), .expect = .{ .op = .send, .proto = .tcp, .family = .v4, .size = test_size, .orient = .endpoint } },
    .{ .name = "11 TCPv4 recv", .id = 11, .payload = v4Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .tcp, .family = .v4, .size = test_size, .orient = .endpoint } },
    .{ .name = "26 TCPv6 send", .id = 26, .payload = v6Payload(&send_trailer), .expect = .{ .op = .send, .proto = .tcp, .family = .v6, .size = test_size, .orient = .endpoint } },
    .{ .name = "27 TCPv6 recv", .id = 27, .payload = v6Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .tcp, .family = .v6, .size = test_size, .orient = .endpoint } },
    .{ .name = "42 UDPv4 send", .id = 42, .payload = v4Payload(&seq_conn), .expect = .{ .op = .send, .proto = .udp, .family = .v4, .size = test_size, .orient = .endpoint } },
    .{ .name = "43 UDPv4 recv", .id = 43, .payload = v4Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .udp, .family = .v4, .size = test_size, .orient = .datagram } },
    .{ .name = "58 UDPv6 send", .id = 58, .payload = v6Payload(&seq_conn), .expect = .{ .op = .send, .proto = .udp, .family = .v6, .size = test_size, .orient = .endpoint } },
    .{ .name = "59 UDPv6 recv", .id = 59, .payload = v6Payload(&seq_conn), .expect = .{ .op = .recv, .proto = .udp, .family = .v6, .size = test_size, .orient = .datagram } },
    // Lifecycle events: maintain the connection list, never carry bytes.
    .{ .name = "12 TCPv4 connect", .id = 12, .payload = v4Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v4, .size = 0, .orient = .endpoint } },
    .{ .name = "15 TCPv4 accept", .id = 15, .payload = v4Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v4, .size = 0, .orient = .endpoint } },
    .{ .name = "13 TCPv4 disconnect", .id = 13, .payload = v4Payload(&seq_conn), .expect = .{ .op = .disconnect, .proto = .tcp, .family = .v4, .size = 0, .orient = .endpoint } },
    .{ .name = "28 TCPv6 connect", .id = 28, .payload = v6Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v6, .size = 0, .orient = .endpoint } },
    .{ .name = "31 TCPv6 accept", .id = 31, .payload = v6Payload(&connect_trailer), .expect = .{ .op = .connect, .proto = .tcp, .family = .v6, .size = 0, .orient = .endpoint } },
    .{ .name = "29 TCPv6 disconnect", .id = 29, .payload = v6Payload(&seq_conn), .expect = .{ .op = .disconnect, .proto = .tcp, .family = .v6, .size = 0, .orient = .endpoint } },
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
            // Both endpoints are asserted per (id, direction), so a
            // re-inversion fails here rather than reaching a Snapshot.
            const want_local_port, const want_remote_port = switch (exp.orient) {
                .endpoint => .{ test_sport, test_dport },
                .datagram => .{ test_dport, test_sport },
            };
            try std.testing.expectEqual(want_local_port, ev.local_port);
            try std.testing.expectEqual(want_remote_port, ev.remote_port);
            switch (exp.family) {
                .v4 => {
                    const want_local, const want_remote = switch (exp.orient) {
                        .endpoint => .{ saddr4, daddr4 },
                        .datagram => .{ daddr4, saddr4 },
                    };
                    try std.testing.expectEqualSlices(u8, &want_local, ev.local_addr[0..4]);
                    try std.testing.expectEqualSlices(u8, &want_remote, ev.remote_addr[0..4]);
                    // v4 fills only the first four bytes of either slot.
                    try std.testing.expectEqualSlices(u8, &(@as([12]u8, @splat(0))), ev.local_addr[4..]);
                    try std.testing.expectEqualSlices(u8, &(@as([12]u8, @splat(0))), ev.remote_addr[4..]);
                },
                .v6 => {
                    const want_local, const want_remote = switch (exp.orient) {
                        .endpoint => .{ saddr6, daddr6 },
                        .datagram => .{ daddr6, saddr6 },
                    };
                    try std.testing.expectEqualSlices(u8, &want_local, &ev.local_addr);
                    try std.testing.expectEqualSlices(u8, &want_remote, &ev.remote_addr);
                },
            }
        } else {
            try std.testing.expectEqual(@as(?NetEvent, null), parsed);
        }
    }
}

/// One socket's two-way conversation, laid out as the provider reports it: our
/// datagram out carries (daddr = them, saddr = us), and their reply in carries
/// that reply datagram's own addresses — so the payload fields arrive
/// mirrored between the two events.
const Conversation = struct {
    send_id: u16,
    recv_id: u16,
    out: []const u8,
    in: []const u8,
    /// The socket's real endpoints, which both events must resolve to.
    want_local: []const u8,
    want_remote: []const u8,
};

const conversations = [_]Conversation{
    .{
        .send_id = Id.udp4_send,
        .recv_id = Id.udp4_recv,
        .out = v4PayloadOf(daddr4, saddr4, test_dport, test_sport, &seq_conn),
        .in = v4PayloadOf(saddr4, daddr4, test_sport, test_dport, &seq_conn),
        .want_local = &saddr4,
        .want_remote = &daddr4,
    },
    .{
        .send_id = Id.udp6_send,
        .recv_id = Id.udp6_recv,
        .out = v6PayloadOf(daddr6, saddr6, test_dport, test_sport, &seq_conn),
        .in = v6PayloadOf(saddr6, daddr6, test_sport, test_dport, &seq_conn),
        .want_local = &saddr6,
        .want_remote = &daddr6,
    },
};

test "a two-way UDP conversation is one Flow, not two mirrored halves (issue #36)" {
    for (conversations) |c| {
        errdefer std.debug.print("conversation {d}/{d} split\n", .{ c.send_id, c.recv_id });
        const sent = parseV0(c.send_id, c.out, 0) orelse return error.ExpectedRecord;
        const received = parseV0(c.recv_id, c.in, 0) orelse return error.ExpectedRecord;

        // Every component of the Flow key (flows.flowKey: protocol, family,
        // owning PID, local endpoint, remote endpoint) has to agree, or the
        // one conversation opens two Flows carrying a direction each.
        try std.testing.expectEqual(sent.pid, received.pid);
        try std.testing.expectEqual(sent.proto, received.proto);
        try std.testing.expectEqual(sent.family, received.family);
        try std.testing.expectEqualSlices(u8, &sent.local_addr, &received.local_addr);
        try std.testing.expectEqualSlices(u8, &sent.remote_addr, &received.remote_addr);
        try std.testing.expectEqual(sent.local_port, received.local_port);
        try std.testing.expectEqual(sent.remote_port, received.remote_port);

        // …and the pair they agree on is the socket's own, not the mirror
        // image: a local endpoint the owning process could have bound, and a
        // remote that is the host at the other end — the side Hostname
        // Attribution names.
        try std.testing.expectEqualSlices(u8, c.want_local, received.local_addr[0..c.want_local.len]);
        try std.testing.expectEqual(test_sport, received.local_port);
        try std.testing.expectEqualSlices(u8, c.want_remote, received.remote_addr[0..c.want_remote.len]);
        try std.testing.expectEqual(test_dport, received.remote_port);
    }
}

test "TCP recv stays endpoint-oriented: one payload shape serves both directions" {
    // Measured live: a TCP send and the matching recv on one socket carry
    // byte-identical saddr/daddr — the fields describe the connection, not
    // the packet. Guards the fix from being over-applied to TCP.
    const payload = comptime v4Payload(&seq_conn);
    const sent = parseV0(Id.tcp4_send, payload, 0) orelse return error.ExpectedRecord;
    const received = parseV0(Id.tcp4_recv, payload, 0) orelse return error.ExpectedRecord;
    for ([_]NetEvent{ sent, received }) |ev| {
        try std.testing.expectEqualSlices(u8, &saddr4, ev.local_addr[0..4]);
        try std.testing.expectEqual(test_sport, ev.local_port);
        try std.testing.expectEqualSlices(u8, &daddr4, ev.remote_addr[0..4]);
        try std.testing.expectEqual(test_dport, ev.remote_port);
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
