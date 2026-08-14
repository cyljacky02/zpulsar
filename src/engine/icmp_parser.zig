//! Fixed-offset parsing of Microsoft-Windows-TCPIP event 1422 (`IcmpSendRecv`)
//! into NetEvent records (docs/research/icmp-visibility.md §2; ADR-0003).
//! One event per ICMP message, both directions. There is no user-mode ICMP
//! byte source, so these records carry `size = 0` and count as messages
//! (core.zig) — ICMP provably contributes nothing to any byte total.
//!
//! Attribution is the ETW record header's ProcessId, which on the send path
//! is the real calling process including the `IcmpSendEcho` path (research
//! §4). The receive path logs at PID 4 in arbitrary DPC context, so inbound
//! records carry `pid = 0`: they are correlated to a live Flow downstream
//! (flows.zig) or dropped, never attributed to System.
//!
//! Version-dispatched like the other parsers: only v0 is implemented and an
//! unknown version drops rather than misparsing. There is no TDH fallback
//! here — the template's length-prefixed `win:Binary` addresses are exactly
//! the shape tdh.zig's flat offset derivation refuses.

const std = @import("std");
const event = @import("event.zig");

/// Microsoft-Windows-TCPIP event ids on the `ut:Global` keyword
/// (provider manifest, Windows 11 build 26200).
pub const Id = struct {
    pub const icmp_send_recv: u16 = 1422;
};

/// `IPTransportProtocol`: the IANA protocol number, which also selects the
/// ICMP type numbering (ICMPv6 renumbered echo — RFC 4443).
const proto_icmpv4: u32 = 1;
const proto_icmpv6: u32 = 58;

/// `PathDirection` (verified live: `ping` logs its echo requests as 0 in its
/// own process context, the replies as 1 at PID 4).
const direction_send: u32 = 0;
const direction_receive: u32 = 1;

/// ws2def.h `AF_INET` / `AF_INET6`, as they appear in the payload's
/// `SOCKADDR` blobs. Declared here rather than imported so this parser stays
/// std-only like its siblings; the facade comptime-asserts the same values
/// against the SDK, so a drift there is a compile error over in win32.zig.
const af_inet: u16 = 2;
const af_inet6: u16 = 23;

/// Template v0 (provider manifest): IPTransportProtocol, PathDirection,
/// IcmpType, IcmpCode, CompartmentId, SourceAddressLength — six u32 — then
/// the length-prefixed SourceAddress, DestAddressLength, and DestAddress.
const fixed_prefix_len = 24;

/// Parse one TCPIP record. `header_pid` is `EVENT_HEADER.ProcessId`; it is
/// the record's only source of attribution and is kept on the send path only.
pub fn parse(
    id: u16,
    version: u8,
    user_data: []const u8,
    header_pid: u32,
    timestamp_ft: i64,
) ?event.NetEvent {
    if (id != Id.icmp_send_recv or version != 0) return null;
    if (user_data.len < fixed_prefix_len) return null;

    const family: event.Family = switch (std.mem.readInt(u32, user_data[0..4], .little)) {
        proto_icmpv4 => .v4,
        proto_icmpv6 => .v6,
        else => return null,
    };
    const op: event.Op = switch (std.mem.readInt(u32, user_data[4..8], .little)) {
        direction_send => .send,
        direction_receive => .recv,
        else => return null,
    };
    const icmp_type = std.math.cast(
        u8,
        std.mem.readInt(u32, user_data[8..12], .little),
    ) orelse return null;

    // IcmpCode (12) and CompartmentId (16) are read by nothing downstream.
    const source = readAddressField(user_data, 20) orelse return null;
    const dest = readAddressField(user_data, source.next_off) orelse return null;

    // The peer is whichever end is not this machine. Under the `ut:Global`
    // keyword the send path logs both lengths as zero (ADR-0003), so an
    // outbound record's remote address is simply unknown — the Flow learns
    // it from the correlated replies instead.
    const remote_field = if (op == .send) dest else source;
    const remote_addr: [16]u8 = if (remote_field.bytes.len == 0)
        @splat(0)
    else
        sockaddrAddress(family, remote_field.bytes) orelse return null;

    return .{
        .op = op,
        .proto = .icmp,
        .family = family,
        .icmp_type = icmp_type,
        // Inbound ICMP is logged in arbitrary DPC context: the header PID is
        // System, never the conversation's owner. Zeroing it here makes
        // "no phantom System-row activity" structural.
        .pid = if (op == .send) header_pid else 0,
        // No user-mode source reports ICMP message sizes (research §Verdict).
        .size = 0,
        // ICMP Flow identity is (protocol, family, owning PID) — no local
        // endpoint, no ports (ADR-0003).
        .local_addr = @splat(0),
        .remote_addr = remote_addr,
        .local_port = 0,
        .remote_port = 0,
        .timestamp_ft = timestamp_ft,
    };
}

const AddressField = struct {
    bytes: []const u8,
    /// Offset of whatever follows this length-prefixed field.
    next_off: usize,
};

/// Read a `win:Binary` field written as a u32 length at `len_off` followed by
/// that many bytes. Null means the payload is too short to hold it.
fn readAddressField(user_data: []const u8, len_off: usize) ?AddressField {
    if (len_off + 4 > user_data.len) return null;
    const len = std.mem.readInt(u32, user_data[len_off..][0..4], .little);
    const start = len_off + 4;
    if (len > user_data.len - start) return null;
    return .{ .bytes = user_data[start..][0..len], .next_off = start + len };
}

/// The address out of a payload `SOCKADDR_IN` / `SOCKADDR_IN6`, as the raw
/// network-order bytes the rest of the Engine normalizes on. A blob whose
/// family contradicts the event's transport protocol is refused rather than
/// read at the wrong offset.
fn sockaddrAddress(family: event.Family, sa: []const u8) ?[16]u8 {
    var out: [16]u8 = @splat(0);
    switch (family) {
        // sin_family, sin_port, sin_addr
        .v4 => {
            if (sa.len < 8) return null;
            if (std.mem.readInt(u16, sa[0..2], .little) != af_inet) return null;
            @memcpy(out[0..4], sa[4..8]);
        },
        // sin6_family, sin6_port, sin6_flowinfo, sin6_addr
        .v6 => {
            if (sa.len < 24) return null;
            if (std.mem.readInt(u16, sa[0..2], .little) != af_inet6) return null;
            @memcpy(out[0..16], sa[8..24]);
        },
    }
    return out;
}

// ---------------------------------------------------------------------------
// Fixtures — the v0 template built field-by-field in the manifest's
// declaration order (spec issue #18, Testing Decisions). The builders ARE the
// layout: change an offset and the payload bytes change with it. Field values
// are the ones captured live (elevated, Windows 11 build 26200) and recorded
// in docs/research/icmp-visibility.md §Addendum.
// ---------------------------------------------------------------------------

fn le32(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    return b;
}

fn le16(v: u16) [2]u8 {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .little);
    return b;
}

const test_pid: u32 = 51752; // the captured ping.exe
const remote4 = [4]u8{ 1, 1, 1, 1 };
const local4 = [4]u8{ 192, 168, 88, 254 };
const loopback6 = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

/// SOCKADDR_IN: sin_family, sin_port, sin_addr, sin_zero — 16 bytes.
fn sockaddr4(addr: [4]u8) [16]u8 {
    return le16(af_inet) ++ [2]u8{ 0, 0 } ++ addr ++ @as([8]u8, @splat(0));
}

/// SOCKADDR_IN6: sin6_family, sin6_port, sin6_flowinfo, sin6_addr,
/// sin6_scope_id — 28 bytes.
fn sockaddr6(addr: [16]u8) [28]u8 {
    return le16(af_inet6) ++ [2]u8{ 0, 0 } ++ le32(0) ++ addr ++ le32(0);
}

/// IPTransportProtocol, PathDirection, IcmpType, IcmpCode, CompartmentId,
/// SourceAddressLength, SourceAddress, DestAddressLength, DestAddress.
/// Call at comptime only — the result references the comptime-materialized
/// array (a runtime call would return a pointer to a dead stack temporary).
fn payload(
    comptime transport: u32,
    comptime direction: u32,
    comptime icmp_type: u32,
    comptime compartment: u32,
    comptime source: []const u8,
    comptime dest: []const u8,
) []const u8 {
    return &(le32(transport) ++ le32(direction) ++ le32(icmp_type) ++
        le32(0) ++ le32(compartment) ++
        le32(source.len) ++ source[0..source.len].* ++
        le32(dest.len) ++ dest[0..dest.len].*);
}

/// The send path under `ut:Global`: both address lengths zero, and the
/// compartment unset — the captured shape (ADR-0003).
fn sendPayload(comptime transport: u32, comptime icmp_type: u32) []const u8 {
    return payload(transport, direction_send, icmp_type, 0, &.{}, &.{});
}

/// The receive path, which does carry both addresses, in compartment 1.
fn recvPayload(
    comptime transport: u32,
    comptime icmp_type: u32,
    comptime source: []const u8,
    comptime dest: []const u8,
) []const u8 {
    return payload(transport, direction_receive, icmp_type, 1, source, dest);
}

const Expect = struct {
    op: event.Op,
    family: event.Family,
    icmp_type: u8,
    pid: u32,
    /// Remote address bytes; empty means "all zero" (unknown peer).
    remote: []const u8 = &.{},
};

const Fixture = struct {
    name: []const u8,
    id: u16 = Id.icmp_send_recv,
    version: u8 = 0,
    payload: []const u8,
    expect: ?Expect,
};

const fixtures = [_]Fixture{
    // The captured `ping -n 3 1.1.1.1` pair.
    .{
        .name = "1422v0 outbound echo request (v4)",
        .payload = sendPayload(proto_icmpv4, 8),
        .expect = .{ .op = .send, .family = .v4, .icmp_type = 8, .pid = test_pid },
    },
    .{
        .name = "1422v0 inbound echo reply (v4)",
        .payload = recvPayload(proto_icmpv4, 0, &sockaddr4(remote4), &sockaddr4(local4)),
        // Inbound carries no attribution: the record must not name System.
        .expect = .{ .op = .recv, .family = .v4, .icmp_type = 0, .pid = 0, .remote = &remote4 },
    },
    // The captured `ping -6 ::1` pair: ICMPv6 renumbers echo to 128/129.
    .{
        .name = "1422v0 outbound echo request (v6)",
        .payload = sendPayload(proto_icmpv6, 128),
        .expect = .{ .op = .send, .family = .v6, .icmp_type = 128, .pid = test_pid },
    },
    .{
        .name = "1422v0 inbound echo reply (v6)",
        .payload = recvPayload(proto_icmpv6, 129, &sockaddr6(loopback6), &sockaddr6(loopback6)),
        .expect = .{ .op = .recv, .family = .v6, .icmp_type = 129, .pid = 0, .remote = &loopback6 },
    },
    // An outbound message that does carry addresses (the shape a build with
    // richer keywords logs) takes its remote from DestAddress, not Source.
    .{
        .name = "1422v0 outbound with addresses takes the destination",
        .payload = payload(proto_icmpv4, direction_send, 8, 0, &sockaddr4(local4), &sockaddr4(remote4)),
        .expect = .{ .op = .send, .family = .v4, .icmp_type = 8, .pid = test_pid, .remote = &remote4 },
    },
    // Ignored: a future version may move fields, and other ids on the keyword
    // (the session-start rundown burst) are not ours to parse.
    .{ .name = "1422 unknown version drops", .version = 1, .payload = sendPayload(proto_icmpv4, 8), .expect = null },
    .{ .name = "1542 IP neighbor rundown drops", .id = 1542, .payload = sendPayload(proto_icmpv4, 8), .expect = null },
    .{ .name = "1423 ICMP drop event is not ours", .id = 1423, .payload = sendPayload(proto_icmpv4, 8), .expect = null },
    // Malformed: an unknown transport protocol, direction, or type width must
    // never be guessed at.
    .{ .name = "unknown transport protocol drops", .payload = payload(6, direction_send, 8, 0, &.{}, &.{}), .expect = null },
    .{ .name = "unknown path direction drops", .payload = payload(proto_icmpv4, 7, 8, 0, &.{}, &.{}), .expect = null },
    .{ .name = "an ICMP type wider than a byte drops", .payload = payload(proto_icmpv4, direction_send, 256, 0, &.{}, &.{}), .expect = null },
    // A SOCKADDR whose family contradicts the transport protocol would be
    // read at the wrong offset: refuse it.
    .{
        .name = "mismatched sockaddr family drops",
        .payload = recvPayload(proto_icmpv6, 129, &sockaddr4(remote4), &sockaddr4(local4)),
        .expect = null,
    },
};

test "fixtures: every (id, version) layout parses to its record or to nothing" {
    for (fixtures) |f| {
        errdefer std.debug.print("fixture failed: {s}\n", .{f.name});
        const parsed = parse(f.id, f.version, f.payload, test_pid, 777);
        const exp = f.expect orelse {
            try std.testing.expectEqual(@as(?event.NetEvent, null), parsed);
            continue;
        };
        const ev = parsed orelse return error.ExpectedRecord;
        try std.testing.expectEqual(event.Proto.icmp, ev.proto);
        try std.testing.expectEqual(exp.op, ev.op);
        try std.testing.expectEqual(exp.family, ev.family);
        try std.testing.expectEqual(exp.icmp_type, ev.icmp_type);
        try std.testing.expectEqual(exp.pid, ev.pid);
        try std.testing.expectEqual(@as(i64, 777), ev.timestamp_ft);
        // No user-mode ICMP byte source exists: records never carry bytes.
        try std.testing.expectEqual(@as(u32, 0), ev.size);
        // ICMP identity carries no local endpoint and no ports.
        try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &ev.local_addr);
        try std.testing.expectEqual(@as(u16, 0), ev.local_port);
        try std.testing.expectEqual(@as(u16, 0), ev.remote_port);
        var want: [16]u8 = @splat(0);
        @memcpy(want[0..exp.remote.len], exp.remote);
        try std.testing.expectEqualSlices(u8, &want, &ev.remote_addr);
    }
}

// Raw `UserData` bytes taken off a live `zPulsarNet` session (elevated,
// Windows 11 build 26200) during `ping -n 2 1.1.1.1` and `ping -6 -n 2 ::1`,
// reproduced in docs/research/icmp-visibility.md §Addendum. The builders
// above express the layout, but a builder written from a wrong assumption
// would encode that assumption consistently and prove nothing — these pin it
// to what the provider actually writes.
const captured_send_v4 = [_]u8{
    0x01, 0x00, 0x00, 0x00, // IPTransportProtocol = 1 (ICMPv4)
    0x00, 0x00, 0x00, 0x00, // PathDirection = 0 (send)
    0x08, 0x00, 0x00, 0x00, // IcmpType = 8 (echo request)
    0x00, 0x00, 0x00, 0x00, // IcmpCode = 0
    0x00, 0x00, 0x00, 0x00, // CompartmentId = 0
    0x00, 0x00, 0x00, 0x00, // SourceAddressLength = 0
    0x00, 0x00, 0x00, 0x00, // DestAddressLength = 0
};

const captured_recv_v4 = [_]u8{
    0x01, 0x00, 0x00, 0x00, // IPTransportProtocol = 1
    0x01, 0x00, 0x00, 0x00, // PathDirection = 1 (receive)
    0x00, 0x00, 0x00, 0x00, // IcmpType = 0 (echo reply)
    0x00, 0x00, 0x00, 0x00, // IcmpCode = 0
    0x01, 0x00, 0x00, 0x00, // CompartmentId = 1
    0x10, 0x00, 0x00, 0x00, // SourceAddressLength = 16
    0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, // AF_INET, port 0, 1.1.1.1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sin_zero
    0x10, 0x00, 0x00, 0x00, // DestAddressLength = 16
    0x02, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x58, 0xfe, // AF_INET, port 0, 192.168.88.254
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

const captured_send_v6 = [_]u8{
    0x3a, 0x00, 0x00, 0x00, // IPTransportProtocol = 58 (ICMPv6)
    0x00, 0x00, 0x00, 0x00, // PathDirection = 0 (send)
    0x80, 0x00, 0x00, 0x00, // IcmpType = 128 (echo request, RFC 4443)
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

test "the fixture builders reproduce the bytes the provider actually writes" {
    try std.testing.expectEqualSlices(
        u8,
        &captured_send_v4,
        comptime sendPayload(proto_icmpv4, 8),
    );
    try std.testing.expectEqualSlices(
        u8,
        &captured_recv_v4,
        comptime recvPayload(proto_icmpv4, 0, &sockaddr4(remote4), &sockaddr4(local4)),
    );
    try std.testing.expectEqualSlices(
        u8,
        &captured_send_v6,
        comptime sendPayload(proto_icmpv6, 128),
    );
}

test "captured payloads parse to the records the Engine acts on" {
    // The send path: real attribution, no peer to name.
    const out = parse(1422, 0, &captured_send_v4, 60732, 1).?;
    try std.testing.expectEqual(event.Op.send, out.op);
    try std.testing.expectEqual(event.Family.v4, out.family);
    try std.testing.expectEqual(@as(u8, 8), out.icmp_type);
    try std.testing.expectEqual(@as(u32, 60732), out.pid);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &out.remote_addr);

    // The receive path: the peer is SourceAddress, and the header PID (4,
    // System) is discarded rather than attributed.
    const in = parse(1422, 0, &captured_recv_v4, 4, 2).?;
    try std.testing.expectEqual(event.Op.recv, in.op);
    try std.testing.expectEqual(@as(u8, 0), in.icmp_type);
    try std.testing.expectEqual(@as(u32, 0), in.pid);
    try std.testing.expectEqualSlices(u8, &remote4, in.remote_addr[0..4]);

    const out6 = parse(1422, 0, &captured_send_v6, 54176, 3).?;
    try std.testing.expectEqual(event.Family.v6, out6.family);
    try std.testing.expectEqual(@as(u8, 128), out6.icmp_type);
}

test "truncated payloads parse to nothing" {
    const send = comptime sendPayload(proto_icmpv4, 8);
    const recv = comptime recvPayload(proto_icmpv4, 0, &sockaddr4(remote4), &sockaddr4(local4));
    // One byte short of the fixed prefix (through SourceAddressLength).
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, send[0..23], 1, 0));
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, &.{}, 1, 0));
    // The prefix alone: DestAddressLength is missing.
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, send[0..24], 1, 0));
    // A SourceAddressLength longer than the bytes that follow it.
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, recv[0..30], 1, 0));
    // Ends inside DestAddress.
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, recv[0 .. recv.len - 1], 1, 0));
    // Exactly the read length still parses.
    try std.testing.expect(parse(1422, 0, send, 1, 0) != null);
    try std.testing.expect(parse(1422, 0, recv, 1, 0) != null);
}

test "a SOCKADDR cut short of its address drops rather than reading past it" {
    // A v6-length field that stops inside sin6_addr, and a v4 field that
    // stops inside sin_addr.
    const short6 = comptime recvPayload(proto_icmpv6, 129, &@as([20]u8, sockaddr6(loopback6)[0..20].*), &.{});
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, short6, 1, 0));
    const short4 = comptime recvPayload(proto_icmpv4, 0, &@as([6]u8, sockaddr4(remote4)[0..6].*), &.{});
    try std.testing.expectEqual(@as(?event.NetEvent, null), parse(1422, 0, short4, 1, 0));
}
