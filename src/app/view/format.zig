//! How the window renders numbers and names. Pure text — no dvui, no win32 —
//! so the rules the spec fixes (decimal units, idle as a dash, ICMP in
//! messages) are testable without a GPU. Every function writes into a
//! caller-owned buffer: the frame path allocates nothing.

const std = @import("std");

/// Longest string `bytes` can produce ("1023.9 TB").
pub const bytes_buf_len = 16;
/// Longest string `rate` can produce (a `bytes` result plus "/s").
pub const rate_buf_len = bytes_buf_len + 2;

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

/// Nothing to show. Not "0": a zero invites the reader to compare it, and
/// there is nothing to compare.
pub const idle = "—";

/// A row with no identity yet — traffic that raced the process rundown, or an
/// event loss that ate it. Never blank: a blank cell reads as a rendering bug.
pub const unnamed = "?";

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
