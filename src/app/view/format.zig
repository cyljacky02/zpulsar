//! How the window renders numbers and names. Pure text — no dvui, no win32 —
//! so the rules the spec fixes (decimal units, idle as a dash, ICMP in
//! messages) are testable without a GPU. Every function writes into a
//! caller-owned buffer: the frame path allocates nothing.

const std = @import("std");
const engine = @import("engine");

const snapshot = engine.snapshot;

/// Longest string `bytes` can produce ("1023.9 TB").
pub const bytes_buf_len = 16;
/// Longest string `rate` can produce (a `bytes` result plus "/s").
pub const rate_buf_len = bytes_buf_len + 2;
/// Longest string `endpoint` can produce: an uncompressible v6 address,
/// bracketed, with the widest port ("[ffff:…:ffff]:65535").
pub const endpoint_buf_len = 48;
/// Longest string `msgs` can produce (a u64 plus " msgs").
pub const msgs_buf_len = 26;

/// Decimal units per the spec's display rules (B/KB/MB/GB). Zero is a dash: a
/// table where most rows have moved nothing is the normal case, and a column
/// of "0 B" hides the rows that matter.
///
/// The headless rig (src/headless/main.zig) climbs the same ladder in its own
/// code and deliberately parts company here — it prints "0 B", because a debug
/// rig wants the number it actually read. Two surfaces, two audiences; only
/// this one owes the spec its zero-value rule.
pub fn bytes(buf: []u8, v: u64) []const u8 {
    if (v == 0) return idle;
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var val: f64 = @floatFromInt(v);
    var unit: usize = 0;
    while (val >= 1000 and unit + 1 < units.len) : (unit += 1) val /= 1000;
    return if (unit == 0)
        std.fmt.bufPrint(buf, "{d} B", .{v}) catch "?"
    else
        std.fmt.bufPrint(buf, "{d:.1} {s}", .{ val, units[unit] }) catch "?";
}

/// A Snapshot's precomputed speed. Idle reads as a dash rather than "0 B/s" —
/// the spec's zero-value rule, and the difference between a table you can scan
/// and a wall of zeroes.
pub fn rate(buf: []u8, bytes_per_s: u64) []const u8 {
    if (bytes_per_s == 0) return idle;
    var inner: [bytes_buf_len]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}/s", .{bytes(&inner, bytes_per_s)}) catch "?";
}

/// An ICMP Flow's activity, which is message counts and never bytes
/// (CONTEXT.md "ICMP Message Count"). Zero reads as the same dash every other
/// empty cell shows — a flow that has sent nothing back is quiet, not special.
pub fn msgs(buf: []u8, count: u64) []const u8 {
    if (count == 0) return idle;
    return std.fmt.bufPrint(buf, "{d} msgs", .{count}) catch "?";
}

/// Which way traffic went. The two totals columns are the same rule twice, so
/// naming the direction keeps one of them from quietly reading the other's
/// field.
pub const Direction = enum { down, up };

/// What a totals cell counts. Bytes and messages are not convertible and never
/// summed together (CONTEXT.md "ICMP Message Count"); the unit travels with
/// the number so a cell cannot print one as the other.
pub const Volume = union(enum) { bytes: u64, msgs: u64 };

/// A Volume as its column shows it, in its own unit.
pub fn volume(buf: []u8, v: Volume) []const u8 {
    return switch (v) {
        .bytes => |b| bytes(buf, b),
        .msgs => |m| msgs(buf, m),
    };
}

/// Whether a Volume has nothing in it, in whichever unit it counts. What
/// decides that a cell renders dimmed.
pub fn isIdle(v: Volume) bool {
    return switch (v) {
        .bytes => |b| b == 0,
        .msgs => |m| m == 0,
    };
}

/// How a totals column ranks two of its cells. Bytes and messages cannot be
/// weighed against each other, so they are ranked by kind first: a row that
/// moved bytes outranks one that only moved messages, and messages settle the
/// order among the rows that moved none. Without this the column would sort by
/// a number it is not showing.
pub fn compareVolume(a: Volume, b: Volume) std.math.Order {
    if (isIdle(a) or isIdle(b)) {
        // Empty is empty in either unit — and one empty side means there is no
        // cross-unit ranking left to make.
        return std.math.order(@intFromBool(!isIdle(a)), @intFromBool(!isIdle(b)));
    }
    return switch (a) {
        .bytes => |x| switch (b) {
            .bytes => |y| std.math.order(x, y),
            .msgs => .gt,
        },
        .msgs => |x| switch (b) {
            .bytes => .lt,
            .msgs => |y| std.math.order(x, y),
        },
    };
}

/// A Flow's In-session Totals: bytes, or messages when it is ICMP.
pub fn flowVolume(f: snapshot.Flow, dir: Direction) Volume {
    if (f.proto == .icmp) return .{ .msgs = switch (dir) {
        .down => f.msgs_recv,
        .up => f.msgs_sent,
    } };
    return .{ .bytes = switch (dir) {
        .down => f.recv,
        .up => f.sent,
    } };
}

/// A Process Row's In-session Totals. Bytes, unless the row has none and its
/// Flows have messages — a process that only pings would otherwise show an
/// empty line while its own Flows show the messages it sent. One row, one
/// unit: a row with bytes to report reports bytes, and leaves its ICMP Flows
/// to say "N msgs" on their own lines.
///
/// A row whose Flows were evicted has none left to count, so it reports the
/// bytes it kept — Eviction coarsens attribution and the Row carries no
/// message counter of its own (CONTEXT.md "Eviction").
pub fn rowVolume(r: snapshot.Row, dir: Direction) Volume {
    if (r.recv == 0 and r.sent == 0) {
        var recv: u64 = 0;
        var sent: u64 = 0;
        for (r.flows) |f| {
            recv += f.msgs_recv;
            sent += f.msgs_sent;
        }
        if (recv != 0 or sent != 0) return .{ .msgs = switch (dir) {
            .down => recv,
            .up => sent,
        } };
    }
    return .{ .bytes = switch (dir) {
        .down => r.recv,
        .up => r.sent,
    } };
}

/// Nothing to show. Not "0": a zero invites the reader to compare it, and
/// there is nothing to compare.
pub const idle = "—";

/// No endpoint on this side at all — distinct from `idle`, which is a number
/// that came out zero. An ICMP Flow has no local endpoint and names no peer
/// until a reply correlates one (ADR-0003), and a UDP socket that has not
/// spoken yet has no remote.
pub const no_endpoint = "*";

/// A row with no identity yet — traffic that raced the process rundown, or an
/// event loss that ate it. Never blank: a blank cell reads as a rendering bug.
pub const unnamed = "?";

/// Which half of a Flow to render. Naming the side rather than passing the
/// fields keeps a caller from pairing one end's address with the other's port.
pub const Side = enum { local, remote };

/// One end of a Flow, as the Ledger and the Info View show it. ICMP prints
/// bare addresses — it has no ports (ADR-0003) — and an end with neither
/// address nor port says so rather than printing a row of zeroes.
pub fn endpoint(buf: []u8, f: snapshot.Flow, side: Side) []const u8 {
    const addr = switch (side) {
        .local => f.local_addr,
        .remote => f.remote_addr,
    };
    const port = switch (side) {
        .local => f.local_port,
        .remote => f.remote_port,
    };
    if (port == 0 and std.mem.allEqual(u8, &addr, 0)) return no_endpoint;
    return address(buf, f.family, addr, if (f.proto == .icmp) null else port);
}

/// One address, with its port when the protocol has one. A null port gives the
/// bare address — what a Group Address shows, since the port on that
/// conversation is the socket's and already sits on the local endpoint.
pub fn address(buf: []u8, family: engine.event.Family, addr: [16]u8, port: ?u16) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    switch (family) {
        .v4 => w.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch return "?",
        .v6 => {
            // Brackets only when a port follows, so the colons cannot be read
            // as part of the address.
            if (port != null) w.writeByte('[') catch return "?";
            writeV6(&w, addr) catch return "?";
            if (port != null) w.writeByte(']') catch return "?";
        },
    }
    if (port) |p| w.print(":{d}", .{p}) catch return "?";
    return w.buffered();
}

/// A v6 address in the form RFC 5952 fixes: lowercase hex, no leading zeroes,
/// and the longest run of zero groups — leftmost on a tie, never a run of one
/// — collapsed to "::". Full form is 39 characters and would swallow the
/// Process column and the Info View's dock alike.
fn writeV6(w: *std.Io.Writer, addr: [16]u8) !void {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*g, i| g.* = std.mem.readInt(u16, addr[i * 2 ..][0..2], .big);

    var run_start: usize = 0;
    var run_len: usize = 0;
    var i: usize = 0;
    while (i < groups.len) {
        if (groups[i] != 0) {
            i += 1;
            continue;
        }
        var j = i;
        while (j < groups.len and groups[j] == 0) j += 1;
        if (j - i > run_len) {
            run_len = j - i;
            run_start = i;
        }
        i = j;
    }
    // A single zero group writes as "0": "::" would save nothing and reads as
    // more elision than happened.
    if (run_len < 2) run_len = 0;

    var g: usize = 0;
    var need_sep = false;
    while (g < groups.len) {
        if (run_len != 0 and g == run_start) {
            try w.writeAll("::");
            g += run_len;
            need_sep = false;
            continue;
        }
        if (need_sep) try w.writeByte(':');
        try w.print("{x}", .{groups[g]});
        need_sep = true;
        g += 1;
    }
}

/// The letter on a Process Row's badge: the exe's initial, standing in for the
/// real exe icon (locked layout, issue #10). Names that start with punctuation
/// — the Evicted-processes Row's "(evicted processes)" — and rows with no name
/// yet fall back rather than badging a bracket.
pub fn initial(display_path: []const u8) u8 {
    // `processName` never returns an empty slice — an empty path comes back as
    // `unnamed` — so there is always a first byte to look at.
    const c = processName(display_path)[0];
    return if (std.ascii.isAlphanumeric(c)) std.ascii.toUpper(c) else '?';
}

/// Which badge colour a Process Row gets, out of `slots`. Derived from the exe
/// name so it is the same every frame and across the teardown-recreate cycle
/// that rebuilds every widget — a badge that changed colour between frames
/// would read as a different process.
pub fn paletteSlot(display_path: []const u8, slots: usize) usize {
    std.debug.assert(slots > 0);
    return std.hash.Fnv1a_32.hash(processName(display_path)) % slots;
}

/// The exe name out of a Process Row's display path, which is what a reader
/// scans for. Paths that are not paths — a kernel process's bare payload name,
/// the Evicted-processes Row's label — pass through whole.
pub fn processName(display_path: []const u8) []const u8 {
    if (display_path.len == 0) return unnamed;
    const cut = std.mem.lastIndexOfAny(u8, display_path, "\\/") orelse return display_path;
    const base = display_path[cut + 1 ..];
    // A trailing separator leaves nothing to name it by; show the path.
    return if (base.len == 0) display_path else base;
}

/// Keep the head of `text`, never cutting a multi-byte UTF-8 sequence in half.
/// Used where a fixed-size OS buffer sets the limit (the tray tooltip).
pub fn truncate(text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;
    var end = limit;
    while (end > 0 and text[end] & 0xC0 == 0x80) end -= 1;
    return text[0..end];
}

/// A v4 address in the raw network-order layout a Snapshot carries.
fn testV4(a: u8, b: u8, c: u8, d: u8) [16]u8 {
    var out: [16]u8 = @splat(0);
    out[0..4].* = .{ a, b, c, d };
    return out;
}

/// A v6 address from its eight groups.
fn testV6(groups: [8]u16) [16]u8 {
    var out: [16]u8 = undefined;
    for (groups, 0..) |g, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], g, .big);
    return out;
}

test "an endpoint reads address:port, both sides of a Flow" {
    var buf: [endpoint_buf_len]u8 = undefined;
    const f: snapshot.Flow = .{
        .proto = .tcp,
        .family = .v4,
        .local_addr = testV4(192, 168, 1, 10),
        .remote_addr = testV4(23, 55, 98, 114),
        .local_port = 61204,
        .remote_port = 443,
        .generation = 1,
    };
    try std.testing.expectEqualStrings("192.168.1.10:61204", endpoint(&buf, f, .local));
    try std.testing.expectEqualStrings("23.55.98.114:443", endpoint(&buf, f, .remote));
}

test "a v6 endpoint brackets its address and compresses its zeroes" {
    var buf: [endpoint_buf_len]u8 = undefined;
    const f: snapshot.Flow = .{
        .proto = .tcp,
        .family = .v6,
        .local_addr = testV6(.{ 0xfe80, 0, 0, 0, 0x1c2f, 0, 0, 1 }),
        .remote_addr = testV6(.{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 }),
        .local_port = 51000,
        .remote_port = 443,
        .generation = 1,
    };
    // RFC 5952: one run only, and the longest one — the second run of zeroes
    // here stays written out.
    try std.testing.expectEqualStrings("[fe80::1c2f:0:0:1]:51000", endpoint(&buf, f, .local));
    try std.testing.expectEqualStrings("[2001:db8::1]:443", endpoint(&buf, f, .remote));
}

test "ICMP has no ports, and no local side to name" {
    var buf: [endpoint_buf_len]u8 = undefined;
    // ADR-0003: an ICMP Flow has no local endpoint, and no peer until a
    // correlated reply names one.
    var f: snapshot.Flow = .{
        .proto = .icmp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .generation = 1,
    };
    try std.testing.expectEqualStrings(no_endpoint, endpoint(&buf, f, .local));
    try std.testing.expectEqualStrings(no_endpoint, endpoint(&buf, f, .remote));

    f.remote_addr = testV4(8, 8, 8, 8);
    try std.testing.expectEqualStrings("8.8.8.8", endpoint(&buf, f, .remote));
}

test "the declared endpoint buffer holds the widest address a Flow can carry" {
    var buf: [endpoint_buf_len]u8 = undefined;
    const f: snapshot.Flow = .{
        .proto = .tcp,
        .family = .v6,
        // Nothing to compress: the longest text a v6 endpoint can produce.
        .local_addr = testV6(.{ 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff }),
        .remote_addr = @splat(0xff),
        .local_port = 65535,
        .remote_port = 65535,
        .generation = 1,
    };
    try std.testing.expectEqualStrings(
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
        endpoint(&buf, f, .local),
    );
}

test "ICMP counts messages where the byte columns count bytes" {
    var buf: [msgs_buf_len]u8 = undefined;
    // CONTEXT.md "ICMP Message Count": displayed "N msgs", never bytes.
    try std.testing.expectEqualStrings("3 msgs", msgs(&buf, 3));
    // And zero is the same dash every other empty cell shows.
    try std.testing.expectEqualStrings(idle, msgs(&buf, 0));
}

test "a Flow's totals are bytes, unless it is ICMP and they are messages" {
    var buf: [msgs_buf_len]u8 = undefined;
    const tcp: snapshot.Flow = .{
        .proto = .tcp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 1,
        .remote_port = 443,
        .generation = 1,
        .recv = 4000,
        .sent = 1500,
    };
    try std.testing.expectEqualStrings("4.0 KB", volume(&buf, flowVolume(tcp, .down)));
    try std.testing.expectEqualStrings("1.5 KB", volume(&buf, flowVolume(tcp, .up)));

    // ICMP moves no bytes anyone can count (CONTEXT.md "ICMP Message Count"),
    // so its Flows carry messages and its byte fields stay zero.
    const icmp: snapshot.Flow = .{
        .proto = .icmp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .generation = 1,
        .msgs_sent = 4,
        .msgs_recv = 3,
    };
    try std.testing.expectEqualStrings("3 msgs", volume(&buf, flowVolume(icmp, .down)));
    try std.testing.expectEqualStrings("4 msgs", volume(&buf, flowVolume(icmp, .up)));
}

test "a row that moved only messages counts them where its bytes would go" {
    var buf: [msgs_buf_len]u8 = undefined;
    const ping: snapshot.Flow = .{
        .proto = .icmp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .generation = 1,
        .msgs_sent = 4,
        .msgs_recv = 3,
    };
    const flows = [_]snapshot.Flow{ ping, ping };
    const pinger: snapshot.Row = .{ .pid = 1, .name = "C:\\PING.EXE", .flows = &flows };
    try std.testing.expectEqualStrings("6 msgs", volume(&buf, rowVolume(pinger, .down)));
    try std.testing.expectEqualStrings("8 msgs", volume(&buf, rowVolume(pinger, .up)));

    // A row with bytes to its name reports bytes, even while it also pings:
    // one column, one unit, and the ICMP Flow says "N msgs" on its own line.
    const browser: snapshot.Row = .{
        .pid = 2,
        .name = "C:\\chrome.exe",
        .recv = 9000,
        .sent = 0,
        .flows = &flows,
    };
    try std.testing.expectEqualStrings("9.0 KB", volume(&buf, rowVolume(browser, .down)));
    try std.testing.expectEqualStrings(idle, volume(&buf, rowVolume(browser, .up)));

    // And a row with neither is simply quiet.
    const quiet: snapshot.Row = .{ .pid = 3, .name = "C:\\idle.exe" };
    try std.testing.expectEqualStrings(idle, volume(&buf, rowVolume(quiet, .down)));
}

test "a totals column orders what it actually shows" {
    // Bytes and messages are not convertible (CONTEXT.md "ICMP Message
    // Count"), so the column cannot rank one against the other by value. It
    // ranks them by kind: a row that moved bytes outranks one that only ever
    // moved messages, whatever the counts say.
    try std.testing.expectEqual(std.math.Order.gt, compareVolume(.{ .bytes = 1 }, .{ .msgs = 9000 }));
    try std.testing.expectEqual(std.math.Order.lt, compareVolume(.{ .msgs = 9000 }, .{ .bytes = 1 }));

    // Within one unit it is the numbers, which is what makes the header
    // honest: sorting by Down total must not leave the busiest pinger at the
    // bottom of the rows it belongs among.
    try std.testing.expectEqual(std.math.Order.gt, compareVolume(.{ .msgs = 9 }, .{ .msgs = 3 }));
    try std.testing.expectEqual(std.math.Order.lt, compareVolume(.{ .bytes = 10 }, .{ .bytes = 20 }));
    try std.testing.expectEqual(std.math.Order.eq, compareVolume(.{ .bytes = 7 }, .{ .bytes = 7 }));

    // An empty row is empty in either unit: nothing moved is nothing moved,
    // and a tie here falls to the row key like any other (order.zig).
    try std.testing.expectEqual(std.math.Order.eq, compareVolume(.{ .bytes = 0 }, .{ .msgs = 0 }));
    try std.testing.expectEqual(std.math.Order.lt, compareVolume(.{ .bytes = 0 }, .{ .msgs = 1 }));
}

test "a badge letter is the exe's initial, and always something" {
    try std.testing.expectEqual(@as(u8, 'C'), initial("C:\\Program Files\\chrome.exe"));
    try std.testing.expectEqual(@as(u8, 'S'), initial("System"));
    // The Evicted-processes Row is named "(evicted processes)" — a bracket is
    // no initial, so it falls back rather than badging punctuation.
    try std.testing.expectEqual(@as(u8, '?'), initial("(evicted processes)"));
    try std.testing.expectEqual(@as(u8, '?'), initial(""));
}

test "a row's badge colour is its own, and the same one every frame" {
    // Stable across calls: the badge must not flicker between frames, or
    // across the teardown-recreate cycle that rebuilds every widget.
    const chrome = paletteSlot("C:\\Program Files\\chrome.exe", 8);
    try std.testing.expectEqual(chrome, paletteSlot("C:\\Program Files\\chrome.exe", 8));
    // By the exe, not the path it sits in: two copies of one program badge
    // alike.
    try std.testing.expectEqual(chrome, paletteSlot("D:\\other\\chrome.exe", 8));
    try std.testing.expect(chrome < 8);
    // A row with no name yet still gets a slot rather than an out-of-range one.
    try std.testing.expect(paletteSlot("", 8) < 8);
}

test "byte totals climb the decimal ladder the spec fixed" {
    var buf: [bytes_buf_len]u8 = undefined;
    try std.testing.expectEqualStrings("999 B", bytes(&buf, 999));
    // Decimal, not binary: 1000 is the step, so 1024 is already past it.
    try std.testing.expectEqualStrings("1.0 KB", bytes(&buf, 1000));
    try std.testing.expectEqualStrings("1.5 MB", bytes(&buf, 1_500_000));
    try std.testing.expectEqualStrings("2.0 GB", bytes(&buf, 2_000_000_000));
    // The ladder stops at TB rather than inventing units nobody reads.
    try std.testing.expectEqualStrings("18446744.1 TB", bytes(&buf, std.math.maxInt(u64)));
}

test "idle reads as a dash, everywhere a number could have gone" {
    var buf: [rate_buf_len]u8 = undefined;
    try std.testing.expectEqualStrings(idle, rate(&buf, 0));
    var bbuf: [bytes_buf_len]u8 = undefined;
    try std.testing.expectEqualStrings(idle, bytes(&bbuf, 0));
    try std.testing.expectEqualStrings("1.2 KB/s", rate(&buf, 1234));
}

test "the declared buffer sizes actually hold the widest output" {
    var buf: [bytes_buf_len]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, "?", bytes(&buf, std.math.maxInt(u64))));
    var rbuf: [rate_buf_len]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, "?", rate(&rbuf, std.math.maxInt(u64))));
}

test "a row is named by its exe, and by whatever it has when that is not a path" {
    try std.testing.expectEqualStrings("chrome.exe", processName("C:\\Program Files\\chrome.exe"));
    // Kernel and minimal processes carry a bare payload name (issue #21).
    try std.testing.expectEqualStrings("Registry", processName("Registry"));
    // The Evicted-processes Row says what it is in its own name (CONTEXT.md).
    try std.testing.expectEqualStrings("(evicted processes)", processName("(evicted processes)"));
    // An unconverted NT device path still ends in the exe.
    try std.testing.expectEqualStrings("svchost.exe", processName("\\Device\\HarddiskVolume3\\Windows\\svchost.exe"));
    try std.testing.expectEqualStrings(unnamed, processName(""));
    // Degenerate shapes name themselves rather than rendering a blank cell.
    try std.testing.expectEqualStrings("C:\\dir\\", processName("C:\\dir\\"));
}

test "truncation never splits a UTF-8 sequence" {
    // Three 2-byte characters: a 5-byte limit has to stop at 4.
    const text = "ααα";
    try std.testing.expectEqualStrings("αα", truncate(text, 5));
    try std.testing.expectEqualStrings(text, truncate(text, 6));
    try std.testing.expectEqualStrings(text, truncate(text, 99));
    try std.testing.expectEqualStrings("", truncate(text, 1));
}
