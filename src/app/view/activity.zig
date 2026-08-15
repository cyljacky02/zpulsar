//! How busy a cell looks. The Ledger tints its Down and Up cells by speed
//! (locked layout, issue #10), and the scale is the whole point: network
//! speeds span five orders of magnitude, so a linear fill would leave every
//! ordinary transfer indistinguishable from idle and only ever light up during
//! a download. Pure — no dvui — so the curve is testable without a device.

const std = @import("std");

/// Where a fill starts. Decimal, like every other number the window prints:
/// the spec's display rules are decimal (format.zig), and a scale whose ends
/// disagreed with the column they tint would be its own bug.
pub const floor_bytes_per_s: u64 = 1_000;
/// Where a fill is full. Chosen for the link most machines actually have —
/// 50 MB/s saturates a gigabit connection, so the top of the scale is a speed
/// a reader can reach rather than a theoretical maximum nothing ever hits.
pub const ceiling_bytes_per_s: u64 = 50_000_000;

/// The faintest fill worth drawing, and the strongest one that still leaves
/// the number on top of it readable. Alpha, over the row's own background.
const min_alpha: f32 = 24;
const max_alpha: f32 = 120;

/// How busy this speed looks, 0 to 1: nothing at or below the floor, full at
/// or above the ceiling, and one step per factor of ten in between.
pub fn intensity(bytes_per_s: u64) f32 {
    if (bytes_per_s <= floor_bytes_per_s) return 0;
    if (bytes_per_s >= ceiling_bytes_per_s) return 1;
    const v: f64 = @floatFromInt(bytes_per_s);
    const floor: f64 = @floatFromInt(floor_bytes_per_s);
    const ceiling: f64 = @floatFromInt(ceiling_bytes_per_s);
    return @floatCast(@log(v / floor) / @log(ceiling / floor));
}

/// How strongly to tint a Down or Up cell, or null for a cell that has no
/// business being tinted at all. The colour — green for down, amber for up —
/// is the caller's; only the strength is decided here.
pub fn fillAlpha(bytes_per_s: u64) ?u8 {
    const a = intensity(bytes_per_s);
    if (a <= 0) return null;
    return @intFromFloat(min_alpha + (max_alpha - min_alpha) * a);
}

const testing = std.testing;

test "the scale runs from 1 KB/s to 50 MB/s, and clamps outside it" {
    // Below the floor there is nothing worth showing: background chatter is
    // not activity, and tinting it would leave the table permanently lit.
    try testing.expectEqual(@as(f32, 0), intensity(0));
    try testing.expectEqual(@as(f32, 0), intensity(999));
    try testing.expectEqual(@as(f32, 0), intensity(floor_bytes_per_s));
    // And at the ceiling it is full — a faster link than this is still "as
    // busy as this cell gets".
    try testing.expectEqual(@as(f32, 1), intensity(ceiling_bytes_per_s));
    try testing.expectEqual(@as(f32, 1), intensity(std.math.maxInt(u64)));
}

test "the scale is logarithmic, so KB/s reads apart from MB/s" {
    // The geometric mean of the two ends is the halfway point of a log scale:
    // sqrt(1 KB/s x 50 MB/s) ~ 224 KB/s.
    try testing.expectApproxEqAbs(@as(f32, 0.5), intensity(223_607), 0.001);
    // Which is nothing like the linear midpoint — 25 MB/s is most of the way
    // up, and this is the difference that makes ordinary traffic visible.
    try testing.expect(intensity(25_000_000) > 0.9);
    // Each factor of ten is the same step, wherever it falls.
    const decade = intensity(1_000_000) - intensity(100_000);
    try testing.expectApproxEqAbs(decade, intensity(100_000) - intensity(10_000), 0.001);
}

test "an idle cell has no fill at all, and a busy one is visibly stronger" {
    // "no fill" is not "a very faint fill": an empty column must read as empty.
    try testing.expectEqual(@as(?u8, null), fillAlpha(0));
    try testing.expectEqual(@as(?u8, null), fillAlpha(floor_bytes_per_s));

    const slow = fillAlpha(floor_bytes_per_s + 1) orelse return error.NoFill;
    const fast = fillAlpha(ceiling_bytes_per_s) orelse return error.NoFill;
    // The faintest fill is still a fill, and the strongest is still a tint —
    // the number underneath has to stay readable at both ends.
    try testing.expect(slow > 0);
    try testing.expect(fast > slow);
    try testing.expect(fast < 255);
}
