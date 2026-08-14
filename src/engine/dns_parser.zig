//! Fixed-offset parsing of Microsoft-Windows-DNS-Client event 3008 payloads
//! into DnsEvent records (docs/research/dns-client-etw.md §§2, 4, 5). 3008
//! ("query completed") is the single event that fires in the calling process
//! for every completed resolution — wire query, cache hit, or failure alike —
//! so it is the only DNS event the Engine consumes.
//!
//! Acceptance is deliberately narrow: version 0 only, `QueryStatus == 0`, and
//! at least one address in `QueryResults`. Everything else — the preliminary
//! `QueryType=1` probe (status 87), NXDOMAIN, the timeout noise from
//! DNS-less interfaces — parses to nothing rather than to a wrong name.
//!
//! There is no TDH fallback here, unlike the Kernel-Network and
//! Kernel-Process paths: 3008 has only ever existed as version 0 (research
//! §8), and a future version simply costs observations — the affected Flows
//! fall through the tiers to the reverse-lookup lane and show a dimmed hint
//! instead of a wrong name.

const std = @import("std");
const event = @import("event.zig");

/// Microsoft-Windows-DNS-Client event ids (provider manifest, research §2).
pub const Id = struct {
    pub const query_completed: u16 = 3008;
};

/// Scratch for the decoded `QueryResults` list. Comfortably above the real
/// worst case — a CNAME chain plus `max_dns_addresses` v6 literals — but a
/// bound all the same, so the truncation handling above is load-bearing
/// rather than theoretical.
const max_results_bytes = 4 * event.max_hostname_bytes;

/// Non-address records are prefixed this way in `QueryResults`; the number
/// after it is the DNS record type (research §4).
const type_prefix = "type: ";
/// DNS CNAME record type — the only non-address record the Engine reads.
const cname_type = 5;

pub fn parse(
    id: u16,
    version: u8,
    pid: u32,
    user_data: []const u8,
) ?event.DnsEvent {
    if (id != Id.query_completed or version != 0) return null;

    // QueryName, QueryType (u32), QueryOptions (u64), QueryStatus (u32),
    // QueryResults. The payload is tightly packed, so the u64 load sits at an
    // unaligned offset — legitimate through readInt.
    const name = readWsz(user_data, 0) orelse return null;
    const status_off = name.next + 12;
    if (user_data.len < status_off + 4) return null;
    if (std.mem.readInt(u32, user_data[status_off..][0..4], .little) != 0) return null;
    const results = readWsz(user_data, status_off + 4) orelse return null;

    var out: event.DnsEvent = .{
        .pid = pid,
        .name_len = 0,
        .alias_len = 0,
        .addr_count = 0,
        .name_buf = undefined,
        .alias_buf = undefined,
        .addrs = undefined,
    };
    // A name longer than the record is truncated: display-only, and the DNS
    // wire limit is well inside the buffer anyway.
    out.name_len = @intCast(utf16leToUtf8(&out.name_buf, name.bytes).len);
    if (out.name_len == 0) return null;

    var results_buf: [max_results_bytes]u8 = undefined;
    const converted = utf16leToUtf8(&results_buf, results.bytes);
    var text = results_buf[0..converted.len];
    if (converted.truncated) {
        // The tail token was cut mid-value, and a cut address literal is
        // still a *valid* one ("93.184.216.34" → "93.184.216.3"), which would
        // pin the name to an address nobody resolved. Drop the partial token.
        text = text[0 .. std.mem.lastIndexOfScalar(u8, text, ';') orelse 0];
    }
    fillResults(&out, text);
    // A resolution with nothing to attribute is not an observation.
    if (out.addr_count == 0) return null;
    return out;
}

/// A NUL-terminated UTF-16LE payload string: its bytes (terminator excluded)
/// and the offset just past the terminator. Null when the payload ends before
/// the terminator does.
const Wsz = struct { bytes: []const u8, next: usize };

fn readWsz(user_data: []const u8, start: usize) ?Wsz {
    var i = start;
    while (i + 1 < user_data.len) : (i += 2) {
        if (std.mem.readInt(u16, user_data[i..][0..2], .little) == 0)
            return .{ .bytes = user_data[start..i], .next = i + 2 };
    }
    return null;
}

/// Bytes written, and whether the input ran out of room. Callers that parse
/// the result — as opposed to merely displaying it — must know, because a
/// truncated value can still be well-formed.
const Converted = struct { len: usize, truncated: bool };

/// Payload strings are unaligned, so units are read one at a time rather than
/// reinterpreted as `[]const u16`. Hostnames are ASCII in practice (IDN
/// reaches the resolver as punycode); a lone surrogate — which a hostname
/// cannot legitimately contain — becomes U+FFFD rather than failing the whole
/// observation. Output stops on a whole code point when `out` is full.
fn utf16leToUtf8(out: []u8, bytes: []const u8) Converted {
    var written: usize = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        const unit = std.mem.readInt(u16, bytes[i..][0..2], .little);
        // A surrogate half cannot appear in a hostname; substituting keeps one
        // malformed unit from costing the whole observation.
        const cp: u21 = if (std.unicode.utf16IsHighSurrogate(unit) or
            std.unicode.utf16IsLowSurrogate(unit)) 0xFFFD else unit;
        const len = std.unicode.utf8CodepointSequenceLength(cp) catch unreachable;
        if (written + len > out.len) return .{ .len = written, .truncated = true };
        written += std.unicode.utf8Encode(cp, out[written..]) catch unreachable;
    }
    return .{ .len = written, .truncated = false };
}

/// `QueryResults` is a semicolon-delimited list: address records are bare IP
/// literals, everything else is prefixed `type: <n> <data>` (research §4).
/// The CNAME (type 5) chain precedes the addresses, and its tail is the name
/// those addresses actually belong to.
fn fillResults(out: *event.DnsEvent, results: []const u8) void {
    var it = std.mem.splitScalar(u8, results, ';');
    while (it.next()) |raw| {
        const token = std.mem.trim(u8, raw, " ");
        if (token.len == 0) continue;
        if (std.mem.startsWith(u8, token, type_prefix)) {
            if (cnameData(token)) |alias| {
                const n = @min(alias.len, out.alias_buf.len);
                @memcpy(out.alias_buf[0..n], alias[0..n]);
                out.alias_len = @intCast(n);
            }
            continue;
        }
        if (out.addr_count == event.max_dns_addresses) continue;
        const ip = parseIpLiteral(token) orelse continue;
        out.addrs[out.addr_count] = ip;
        out.addr_count += 1;
    }
}

/// The data of a `type: 5 <name>` token, or null for any other record type.
fn cnameData(token: []const u8) ?[]const u8 {
    const rest = token[type_prefix.len..];
    const space = std.mem.indexOfScalar(u8, rest, ' ') orelse return null;
    const record_type = std.fmt.parseUnsigned(u16, rest[0..space], 10) catch return null;
    if (record_type != cname_type) return null;
    const data = std.mem.trim(u8, rest[space + 1 ..], " ");
    return if (data.len == 0) null else data;
}

/// One address literal, in the canonical naming form: a colon means v6, and
/// `::ffff:a.b.c.d` normalizes to the v4 address it stands for.
fn parseIpLiteral(text: []const u8) ?event.IpAddr {
    var addr: [16]u8 = @splat(0);
    if (std.mem.indexOfScalar(u8, text, ':') == null) {
        if (!parseIp4(text, addr[0..4])) return null;
        return .{ .family = .v4, .addr = addr };
    }
    if (!parseIp6(text, &addr)) return null;
    return (event.IpAddr{ .family = .v6, .addr = addr }).normalized();
}

fn parseIp4(text: []const u8, out: []u8) bool {
    var it = std.mem.splitScalar(u8, text, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i == 4 or part.len == 0 or part.len > 3) return false;
        out[i] = std.fmt.parseUnsigned(u8, part, 10) catch return false;
    }
    return i == 4;
}

fn parseIp6(text: []const u8, out: *[16]u8) bool {
    var addr: [16]u8 = @splat(0);
    const compressed = std.mem.indexOf(u8, text, "::");
    if (compressed) |at| {
        // "::" stands for one run of zero groups, so a second one is invalid.
        if (std.mem.indexOf(u8, text[at + 2 ..], "::") != null) return false;
        const head = fillGroups(text[0..at], &addr) orelse return false;
        var tail_bytes: [16]u8 = @splat(0);
        const tail = fillGroups(text[at + 2 ..], &tail_bytes) orelse return false;
        if (head + tail > addr.len) return false;
        @memcpy(addr[addr.len - tail ..], tail_bytes[0..tail]);
    } else {
        if (fillGroups(text, &addr) != addr.len) return false;
    }
    out.* = addr;
    return true;
}

/// Colon-separated hex groups, with the dotted-quad form allowed as the final
/// group (`::ffff:1.2.3.4`). Returns the bytes written, or null if the text is
/// not a valid group run.
fn fillGroups(text: []const u8, out: *[16]u8) ?usize {
    if (text.len == 0) return 0;
    var written: usize = 0;
    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |group| {
        if (group.len == 0) return null;
        if (std.mem.indexOfScalar(u8, group, '.') != null) {
            if (it.next() != null) return null; // dotted quad must come last
            if (written + 4 > out.len) return null;
            if (!parseIp4(group, out[written..][0..4])) return null;
            return written + 4;
        }
        if (group.len > 4 or written + 2 > out.len) return null;
        const v = std.fmt.parseUnsigned(u16, group, 16) catch return null;
        std.mem.writeInt(u16, out[written..][0..2], v, .big);
        written += 2;
    }
    return written;
}

// ---------------------------------------------------------------------------
// Fixtures — the 3008 payload template built field-by-field in the manifest's
// declaration order, with the `QueryResults` shapes captured live in the
// research doc (§4). The builders ARE the layout: change an offset and the
// payload bytes change with it.
// ---------------------------------------------------------------------------

fn le32(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    return b;
}

fn le64(v: u64) [8]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    return b;
}

/// ASCII → NUL-terminated UTF-16LE payload bytes.
fn wsz(comptime ascii: []const u8) [2 * ascii.len + 2]u8 {
    @setEvalBranchQuota(20 * ascii.len + 1000);
    var b: [2 * ascii.len + 2]u8 = @splat(0);
    for (ascii, 0..) |c, i| b[2 * i] = c;
    return b;
}

/// QueryName, QueryType, QueryOptions, QueryStatus, QueryResults — the whole
/// v0 template (research §2). Call at comptime only; a runtime call would
/// return a pointer to a dead stack temporary.
fn payload(
    comptime name: []const u8,
    comptime query_type: u32,
    comptime status: u32,
    comptime results: []const u8,
) []const u8 {
    return &(wsz(name) ++ le32(query_type) ++ le64(0x2019) ++ le32(status) ++ wsz(results));
}

const test_pid: u32 = 42576;

/// The warm cache-hit trace of §3: a dual-family `getaddrinfo` completes as
/// one QueryType=28 event whose v4 answers are IPv4-mapped v6 literals.
const cache_hit = payload("example.com", 28, 0, "::ffff:104.20.23.154;::ffff:172.66.147.243;");

/// The `www.microsoft.com` A lookup of §4: the CNAME chain precedes the
/// addresses.
const cname_chain = payload(
    "www.microsoft.com",
    1,
    0,
    "type: 5 www.microsoft.com-c-3.edgekey.net;type: 5 e13678.dscb.akamaiedge.net;23.46.90.101;",
);

fn expectAddr(expected: event.IpAddr, actual: event.IpAddr) !void {
    try std.testing.expectEqual(expected.family, actual.family);
    try std.testing.expectEqualSlices(u8, &expected.addr, &actual.addr);
}

fn v4(comptime bytes: [4]u8) event.IpAddr {
    return .{ .family = .v4, .addr = bytes ++ @as([12]u8, @splat(0)) };
}

test "a completed resolution yields the query name and its addresses" {
    const ev = parse(Id.query_completed, 0, test_pid, cache_hit) orelse
        return error.ExpectedRecord;
    try std.testing.expectEqual(test_pid, ev.pid);
    try std.testing.expectEqualStrings("example.com", ev.name());
    try std.testing.expectEqualStrings("", ev.alias());
    try std.testing.expectEqual(@as(usize, 2), ev.addresses().len);
    // IPv4-mapped v6 answers normalize to v4, or they would never match a
    // Kernel-Network Flow's remote address (research §4).
    try expectAddr(v4(.{ 104, 20, 23, 154 }), ev.addresses()[0]);
    try expectAddr(v4(.{ 172, 66, 147, 243 }), ev.addresses()[1]);
}

test "the CNAME chain's tail is kept and never mistaken for an address" {
    const ev = parse(Id.query_completed, 0, test_pid, cname_chain) orelse
        return error.ExpectedRecord;
    try std.testing.expectEqualStrings("www.microsoft.com", ev.name());
    try std.testing.expectEqualStrings("e13678.dscb.akamaiedge.net", ev.alias());
    try std.testing.expectEqual(@as(usize, 1), ev.addresses().len);
    try expectAddr(v4(.{ 23, 46, 90, 101 }), ev.addresses()[0]);
}

test "real IPv6 answers stay v6" {
    const ev = parse(
        Id.query_completed,
        0,
        test_pid,
        payload("cloudflare.com", 28, 0, "2606:4700::6810:85e5;::1;"),
    ) orelse return error.ExpectedRecord;
    try std.testing.expectEqual(@as(usize, 2), ev.addresses().len);
    try expectAddr(.{ .family = .v6, .addr = [16]u8{
        0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x85, 0xe5,
    } }, ev.addresses()[0]);
    try expectAddr(.{ .family = .v6, .addr = [4]u8{ 0, 0, 0, 0 } ++
        [11]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } ++ [1]u8{1} }, ev.addresses()[1]);
}

test "nothing but a successful, non-empty answer becomes an observation" {
    const cases = [_]struct { name: []const u8, p: []const u8 }{
        // Every getaddrinfo emits this preliminary probe first (research §4).
        .{ .name = "QueryType=1 probe, status 87", .p = payload("example.com", 1, 87, "") },
        .{ .name = "NXDOMAIN", .p = payload("nope.invalid", 28, 9003, "") },
        .{ .name = "DNS_INFO_NO_RECORDS", .p = payload("example.com", 28, 9701, "") },
        // The WSL vEthernet adapter's recurring timeout noise (research §4).
        .{ .name = "ERROR_TIMEOUT", .p = payload("example.com", 28, 1460, "") },
        // Success with nothing to attribute.
        .{ .name = "success, empty results", .p = payload("example.com", 28, 0, "") },
        // Success with a CNAME chain but no address record.
        .{ .name = "success, CNAME only", .p = payload("x.example.com", 5, 0, "type: 5 y.example.com;") },
        // Garbage in the address slot must not become an address.
        .{ .name = "success, unparseable results", .p = payload("example.com", 28, 0, "not-an-address;") },
    };
    for (cases) |c| {
        errdefer std.debug.print("case failed: {s}\n", .{c.name});
        try std.testing.expectEqual(@as(?event.DnsEvent, null), parse(Id.query_completed, 0, test_pid, c.p));
    }
}

test "other event ids and unknown versions never reach the fixed offsets" {
    // 3006 (query called) shares the payload prefix but not the meaning.
    try std.testing.expectEqual(@as(?event.DnsEvent, null), parse(3006, 0, test_pid, cache_hit));
    try std.testing.expectEqual(@as(?event.DnsEvent, null), parse(3018, 0, test_pid, cache_hit));
    // A future 3008 version costs observations, never a wrong name.
    try std.testing.expectEqual(@as(?event.DnsEvent, null), parse(Id.query_completed, 1, test_pid, cache_hit));
}

test "truncated payloads parse to nothing" {
    // One byte short of the last field the parser reads (the results NUL).
    try std.testing.expectEqual(
        @as(?event.DnsEvent, null),
        parse(Id.query_completed, 0, test_pid, cache_hit[0 .. cache_hit.len - 1]),
    );
    // Cut inside the fixed middle (type/options/status).
    try std.testing.expectEqual(
        @as(?event.DnsEvent, null),
        parse(Id.query_completed, 0, test_pid, cache_hit[0..30]),
    );
    try std.testing.expectEqual(
        @as(?event.DnsEvent, null),
        parse(Id.query_completed, 0, test_pid, &.{}),
    );
}

test "answers beyond the record's capacity are dropped, not wrapped" {
    const many = payload(
        "cdn.example.com",
        1,
        0,
        "1.1.1.1;2.2.2.2;3.3.3.3;4.4.4.4;5.5.5.5;6.6.6.6;7.7.7.7;8.8.8.8;9.9.9.9;10.10.10.10;",
    );
    const ev = parse(Id.query_completed, 0, test_pid, many) orelse return error.ExpectedRecord;
    try std.testing.expectEqual(event.max_dns_addresses, ev.addresses().len);
    try expectAddr(v4(.{ 1, 1, 1, 1 }), ev.addresses()[0]);
    try expectAddr(v4(.{ 8, 8, 8, 8 }), ev.addresses()[event.max_dns_addresses - 1]);
}

test "a results list too long for the buffer never invents a truncated address" {
    // Sized so the decode buffer runs out *inside* the final address literal,
    // leaving exactly "93.184.216.3" — a cut literal that is still perfectly
    // well-formed. Accepting it would pin the name to an address nobody
    // resolved, so the partial token has to be dropped rather than parsed.
    const tail = "93.184.216.34;";
    const cut_at = "93.184.216.3".len;
    const filler_body = "c" ** (max_results_bytes - cut_at - "type: 5 ".len - ";".len);
    const results = "type: 5 " ++ filler_body ++ ";" ++ tail;

    const ev = parse(
        Id.query_completed,
        0,
        test_pid,
        comptime payload("cdn.example.test", 1, 0, results),
    );
    // Only a CNAME survives the trim, so there is nothing left to attribute.
    try std.testing.expectEqual(@as(?event.DnsEvent, null), ev);
}

test "names longer than the record capacity truncate cleanly" {
    const long = "a" ** 400 ++ ".example.com";
    const ev = parse(
        Id.query_completed,
        0,
        test_pid,
        comptime payload(long, 1, 0, "1.2.3.4;"),
    ) orelse return error.ExpectedRecord;
    try std.testing.expectEqual(@as(usize, event.max_hostname_bytes), ev.name().len);
    try std.testing.expectEqualStrings(long[0..event.max_hostname_bytes], ev.name());
}
