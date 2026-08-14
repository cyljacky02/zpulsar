//! Group Addresses: destinations that name a set of receivers rather than one
//! host (ADR-0004). A UDP receive is packet-oriented, so such a destination
//! arrives in the position the Flow's local endpoint is read from — where it
//! cannot stay, because no socket binds a multicast group.
//!
//! Two halves, deliberately separate: the classification is pure and takes the
//! prefix table as a value, so tests never touch Windows; `fetch` is the only
//! part that calls IP Helper. The Engine thread owns the table (ADR-0002) and
//! consults it in `flows.flowKey` — the parser stays a faithful decoder of what
//! the wire said.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");

/// What kind of Group Address a datagram was sent to, if any. Declared in
/// event.zig because it is part of `event.ConnKey` — a group-addressed
/// conversation and a unicast one with the same peer on the same ports are
/// distinct Flows — and re-exported here, where its value is decided.
pub const GroupKind = event.GroupKind;

/// One local unicast address and the on-link prefix it sits in — the fact no
/// event payload carries, and the only thing that makes `192.168.88.255`
/// recognisable as a broadcast address rather than a host.
pub const Prefix = struct {
    family: event.Family,
    /// Raw network-order bytes; v4 occupies the first 4, rest zero.
    addr: [16]u8,
    prefix_len: u8,
};

/// The result of reading a datagram's destination: what it is, and what
/// belongs in the Flow's local endpoint as a result.
pub const Classified = struct {
    kind: GroupKind,
    /// For `.none`, the destination unchanged. For a resolvable directed
    /// broadcast, the receiving interface's own unicast address. Otherwise the
    /// unspecified address — the honest "we know the port, not the interface".
    local_addr: [16]u8,

    /// Nothing to rewrite: the destination is a perfectly good local endpoint.
    fn plain(addr: [16]u8) Classified {
        return .{ .kind = .none, .local_addr = addr };
    }

    fn group(kind: GroupKind, addr: [16]u8) Classified {
        return .{ .kind = kind, .local_addr = addr };
    }
};

const unspecified: [16]u8 = @splat(0);

/// This machine's unicast addresses and their prefixes. `fetch` allocates one;
/// `borrow` wraps a literal for tests. `deinit` is safe on either — a borrowed
/// table points at static memory, and freeing that would be a footgun sitting
/// one `core.deinit()` away.
pub const LocalPrefixes = struct {
    entries: []const Prefix = &.{},
    owned: bool = false,

    pub const empty: LocalPrefixes = .{};

    pub fn borrow(entries: []const Prefix) LocalPrefixes {
        return .{ .entries = entries, .owned = false };
    }

    pub fn deinit(self: *LocalPrefixes, gpa: std.mem.Allocator) void {
        if (self.owned) gpa.free(self.entries);
        self.* = .empty;
    }
};

/// Read a datagram's destination. Classification runs on the normalized
/// address (`event.IpAddr.normalized`) so an IPv4-mapped form cannot slip past
/// the predicate; the returned `local_addr` for `.none` is the caller's own
/// bytes, untouched.
pub fn classify(prefixes: LocalPrefixes, family: event.Family, addr: [16]u8) Classified {
    const norm = (event.IpAddr{ .family = family, .addr = addr }).normalized();
    return switch (norm.family) {
        .v4 => classifyV4(prefixes, norm.addr, addr),
        .v6 => if (norm.addr[0] == 0xff)
            // ff00::/8. IPv6 has no broadcast: an "all nodes on this link"
            // datagram is multicast to ff02::1 like any other group.
            .group(.multicast, unspecified)
        else
            .plain(addr),
    };
}

fn classifyV4(prefixes: LocalPrefixes, norm: [16]u8, original: [16]u8) Classified {
    // 255.255.255.255 — the limited broadcast address. Never forwarded, and it
    // names no subnet, so the receiving interface stays unknowable.
    if (std.mem.allEqual(u8, norm[0..4], 0xff)) return .group(.broadcast, unspecified);

    // 224.0.0.0/4.
    if (norm[0] >= 224 and norm[0] <= 239) return .group(.multicast, unspecified);

    return directedBroadcast(prefixes, norm) orelse .plain(original);
}

/// A subnet-directed broadcast encodes its subnet, so the interface that
/// received it is derivable — but only when exactly one local prefix produces
/// this address. Two interfaces on the same prefix make it ambiguous, and a
/// guess would be exactly the invented data ADR-0004 refuses; that case still
/// classifies as a broadcast, with the local side unspecified.
fn directedBroadcast(prefixes: LocalPrefixes, norm: [16]u8) ?Classified {
    const target = std.mem.readInt(u32, norm[0..4], .big);
    var matches: usize = 0;
    var resolved: [16]u8 = unspecified;
    for (prefixes.entries) |p| {
        if (p.family != .v4) continue;
        const bcast = broadcastOf(p.addr[0..4].*, p.prefix_len) orelse continue;
        if (bcast != target) continue;
        matches += 1;
        resolved = p.addr;
    }
    return switch (matches) {
        0 => null,
        1 => .group(.broadcast, resolved),
        else => .group(.broadcast, unspecified),
    };
}

/// The all-ones host address of `addr`'s subnet. A /31 is point-to-point and a
/// /32 is a host route: neither has a broadcast address, and a /0 names no
/// subnet at all.
fn broadcastOf(addr: [4]u8, prefix_len: u8) ?u32 {
    if (prefix_len == 0 or prefix_len > 30) return null;
    const host_bits: u5 = @intCast(32 - prefix_len);
    const mask: u32 = ~@as(u32, 0) << host_bits;
    const a = std.mem.readInt(u32, &addr, .big);
    return (a & mask) | ~mask;
}

pub const FetchError = error{ OutOfMemory, TableQueryFailed };

/// Snapshot this machine's unicast addresses. Called on the Engine thread at
/// cold start and on the 10 s sweep; the caller keeps the last good table when
/// this fails, so a transient failure degrades to pre-ADR-0004 behaviour rather
/// than to a wrong answer.
pub fn fetch(gpa: std.mem.Allocator) FetchError!LocalPrefixes {
    var table: ?*win32.MIB_UNICASTIPADDRESS_TABLE = null;
    const rc = win32.GetUnicastIpAddressTable(win32.AF_UNSPEC, &table);
    const t = table orelse return error.TableQueryFailed;
    // The table allocates on success; free it whatever we make of the rows.
    defer win32.FreeMibTable(t);
    if (rc != win32.STATUS_SUCCESS) return error.TableQueryFailed;

    const rows = @as([*]const win32.MIB_UNICASTIPADDRESS_ROW, @ptrCast(&t.Table))[0..t.NumEntries];
    var list: std.ArrayList(Prefix) = .empty;
    errdefer list.deinit(gpa);
    try list.ensureUnusedCapacity(gpa, rows.len);
    for (rows) |row| {
        if (prefixFromRow(row)) |p| list.appendAssumeCapacity(p);
    }
    return .{ .entries = try list.toOwnedSlice(gpa), .owned = true };
}

/// `SOCKADDR_INET` is a union; `si_family` picks the arm. Both arms hold their
/// address in network order already, so the bytes copy straight across — read
/// through `asBytes` rather than the generated union field names, which are
/// nested one level deeper than the ABI cares about.
fn prefixFromRow(row: win32.MIB_UNICASTIPADDRESS_ROW) ?Prefix {
    var addr: [16]u8 = unspecified;
    const family: event.Family = switch (row.Address.si_family) {
        win32.AF_INET_FAMILY => blk: {
            @memcpy(addr[0..4], std.mem.asBytes(&row.Address.Ipv4.sin_addr)[0..4]);
            break :blk .v4;
        },
        win32.AF_INET6_FAMILY => blk: {
            @memcpy(&addr, std.mem.asBytes(&row.Address.Ipv6.sin6_addr)[0..16]);
            break :blk .v6;
        },
        else => return null,
    };
    return .{ .family = family, .addr = addr, .prefix_len = row.OnLinkPrefixLength };
}

// ---------------------------------------------------------------------------
// Tests — the prefix table is a value, so none of this needs a live NIC.
// ---------------------------------------------------------------------------

fn v4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    return [4]u8{ a, b, c, d } ++ @as([12]u8, @splat(0));
}

/// The machine from the #41 report: one /24 LAN interface and one /20 WSL
/// bridge, each with its own directed broadcast.
const two_nics: LocalPrefixes = .borrow(&.{
    .{ .family = .v4, .addr = v4(192, 168, 88, 254), .prefix_len = 24 },
    .{ .family = .v4, .addr = v4(172, 17, 64, 1), .prefix_len = 20 },
});

test "multicast classifies from the address bytes alone, in both families" {
    // No prefix table needed: 224.0.0.0/4 and ff00::/8 are self-describing.
    for ([_][16]u8{
        v4(224, 0, 0, 251), // mDNS
        v4(224, 0, 0, 252), // LLMNR
        v4(239, 255, 255, 250), // SSDP
        v4(224, 0, 0, 0), // bottom of the range
        v4(239, 255, 255, 255), // top of the range
    }) |addr| {
        const got = classify(.empty, .v4, addr);
        try std.testing.expectEqual(GroupKind.multicast, got.kind);
        try std.testing.expectEqualSlices(u8, &unspecified, &got.local_addr);
    }

    var mdns6: [16]u8 = @splat(0);
    mdns6[0] = 0xff;
    mdns6[1] = 0x02;
    mdns6[15] = 0xfb;
    const got6 = classify(.empty, .v6, mdns6);
    try std.testing.expectEqual(GroupKind.multicast, got6.kind);
    try std.testing.expectEqualSlices(u8, &unspecified, &got6.local_addr);

    // Just outside the v4 range on either side, and a real v6 address.
    try std.testing.expectEqual(GroupKind.none, classify(.empty, .v4, v4(223, 255, 255, 255)).kind);
    try std.testing.expectEqual(GroupKind.none, classify(.empty, .v4, v4(240, 0, 0, 1)).kind);
    const real_v6 = [16]u8{ 0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x85, 0xe5 };
    try std.testing.expectEqual(GroupKind.none, classify(.empty, .v6, real_v6).kind);
}

test "the limited broadcast address needs no prefix table either" {
    const got = classify(.empty, .v4, v4(255, 255, 255, 255));
    try std.testing.expectEqual(GroupKind.broadcast, got.kind);
    // It names no subnet, so the interface stays unknowable even with a table.
    try std.testing.expectEqualSlices(u8, &unspecified, &classify(two_nics, .v4, v4(255, 255, 255, 255)).local_addr);
}

test "a directed broadcast resolves to the interface that received it" {
    // The #41 repro: Spotify's discovery broadcast on each of two subnets.
    const lan = classify(two_nics, .v4, v4(192, 168, 88, 255));
    try std.testing.expectEqual(GroupKind.broadcast, lan.kind);
    try std.testing.expectEqualSlices(u8, &v4(192, 168, 88, 254), &lan.local_addr);

    // 172.17.64.1/20 spans 172.17.64.0–172.17.79.255.
    const wsl = classify(two_nics, .v4, v4(172, 17, 79, 255));
    try std.testing.expectEqual(GroupKind.broadcast, wsl.kind);
    try std.testing.expectEqualSlices(u8, &v4(172, 17, 64, 1), &wsl.local_addr);

    // The interface's own address, and a plain host on its subnet, are not
    // broadcasts — this is the predicate's whole job.
    try std.testing.expectEqual(GroupKind.none, classify(two_nics, .v4, v4(192, 168, 88, 254)).kind);
    try std.testing.expectEqual(GroupKind.none, classify(two_nics, .v4, v4(192, 168, 88, 7)).kind);
    // /24 means 172.17.79.255 would NOT be this interface's broadcast; the /20
    // is what makes it one. Same address, different prefix, different answer.
    const narrow: LocalPrefixes = .{ .entries = &.{
        .{ .family = .v4, .addr = v4(172, 17, 64, 1), .prefix_len = 24 },
    } };
    try std.testing.expectEqual(GroupKind.none, classify(narrow, .v4, v4(172, 17, 79, 255)).kind);
}

test "resolution is refused rather than guessed" {
    // No prefix produces this address: it is somebody else's broadcast, and
    // from here indistinguishable from a host. Left alone entirely.
    const unknown = classify(two_nics, .v4, v4(10, 1, 2, 255));
    try std.testing.expectEqual(GroupKind.none, unknown.kind);
    try std.testing.expectEqualSlices(u8, &v4(10, 1, 2, 255), &unknown.local_addr);

    // Two interfaces on one subnet: still a broadcast, but naming either would
    // be inventing the answer, so the local side stays unspecified.
    const dual: LocalPrefixes = .{ .entries = &.{
        .{ .family = .v4, .addr = v4(192, 168, 88, 254), .prefix_len = 24 },
        .{ .family = .v4, .addr = v4(192, 168, 88, 99), .prefix_len = 24 },
    } };
    const ambiguous = classify(dual, .v4, v4(192, 168, 88, 255));
    try std.testing.expectEqual(GroupKind.broadcast, ambiguous.kind);
    try std.testing.expectEqualSlices(u8, &unspecified, &ambiguous.local_addr);

    // An empty table (the fetch failed, or none has run yet) degrades to
    // pre-ADR-0004 behaviour: multicast still works, directed broadcast reads
    // as the unicast address it is indistinguishable from.
    try std.testing.expectEqual(GroupKind.none, classify(.empty, .v4, v4(192, 168, 88, 255)).kind);
}

test "prefix lengths without a broadcast address are skipped" {
    // /31 is point-to-point (RFC 3021), /32 is a host route, /0 names no
    // subnet: none of them has an all-ones host address to match against.
    for ([_]u8{ 0, 31, 32 }) |len| {
        const p: LocalPrefixes = .{ .entries = &.{
            .{ .family = .v4, .addr = v4(192, 168, 88, 254), .prefix_len = len },
        } };
        try std.testing.expectEqual(GroupKind.none, classify(p, .v4, v4(192, 168, 88, 255)).kind);
        try std.testing.expectEqual(GroupKind.none, classify(p, .v4, v4(255, 255, 255, 254)).kind);
    }
    // A /30's broadcast is the top of its four-address block.
    const p30: LocalPrefixes = .{ .entries = &.{
        .{ .family = .v4, .addr = v4(10, 0, 0, 5), .prefix_len = 30 },
    } };
    const got = classify(p30, .v4, v4(10, 0, 0, 7));
    try std.testing.expectEqual(GroupKind.broadcast, got.kind);
    try std.testing.expectEqualSlices(u8, &v4(10, 0, 0, 5), &got.local_addr);
}

test "an IPv4-mapped multicast address cannot slip past the predicate" {
    // A dual-stack socket's v6 events can carry the mapped form; classifying
    // the raw bytes would read 0x00 as the first octet and miss the group.
    const mapped = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++ [4]u8{ 224, 0, 0, 251 };
    const got = classify(.empty, .v6, mapped);
    try std.testing.expectEqual(GroupKind.multicast, got.kind);
    try std.testing.expectEqualSlices(u8, &unspecified, &got.local_addr);
}

test "v6 prefixes never produce a broadcast match" {
    // IPv6 has no broadcast address at all, so a v6 row in the table must not
    // participate in the directed-broadcast scan.
    const mixed: LocalPrefixes = .{ .entries = &.{
        .{ .family = .v6, .addr = @splat(0xff), .prefix_len = 24 },
        .{ .family = .v4, .addr = v4(192, 168, 88, 254), .prefix_len = 24 },
    } };
    const got = classify(mixed, .v4, v4(192, 168, 88, 255));
    try std.testing.expectEqual(GroupKind.broadcast, got.kind);
    try std.testing.expectEqualSlices(u8, &v4(192, 168, 88, 254), &got.local_addr);
}
