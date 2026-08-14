//! Rate rings (issue #23; spec issue #18 Data model "Rates"): bytes bucket by
//! **event time**, never arrival time — ETW delivery is flush-bursty, so a
//! second's worth of records can land in one drain and would read as a spike.
//! Sixteen 100 ms buckets (1.6 s) give late arrivals room to land in the
//! bucket they belong to; the displayed speed is a 1 s sliding window over
//! ten of them. Flows and Rows each own a ring (double-bucketed at event
//! time), so a Row's speed survives the eviction of the Flows that earned it.
//!
//! **Every time in this module is event-clock milliseconds** — the domain ETW
//! stamps event headers in (FILETIME ticks / 10 000), not the Engine's
//! monotonic tick. Both ends of a window read the same clock, so a wall-clock
//! step moves the data and the window together and can distort at most the
//! buckets it lands between. Lifecycle timing (Linger, age-out) stays on the
//! monotonic clock, where a step must not reach.
//!
//! The ring is display state, not accounting state: In-session Totals are
//! independent u64 accumulators (core.zig, flows.zig). An arrival later than
//! the ring's 1.6 s of history is missing from the *rate* only — its bytes
//! are already in the totals.

const std = @import("std");

pub const bucket_ms: u64 = 100;
/// 1.6 s of history: the 1 s window, plus the slack below.
pub const bucket_count: u64 = 16;
/// Displayed speed = 1 s sliding window (spec: 10 buckets).
pub const window_buckets: u64 = 10;
/// How far behind the caller's clock the window may sit, in buckets — the
/// ring's spare capacity, and the reason it holds 16 rather than 10. ETW
/// delivers on a flush tick (100–150 ms window-open, 1 s Tray-idle), so the
/// freshest buckets are always still filling: a window pinned to *now* would
/// read a starved fraction of the truth on every flush cycle.
pub const slack_buckets: u64 = bucket_count - window_buckets;

/// FILETIME is 100 ns ticks; this is the one conversion into the event clock.
pub const ft_ticks_per_ms: u64 = std.time.ns_per_ms / 100;

pub fn msFromFileTime(ticks: u64) u64 {
    return ticks / ft_ticks_per_ms;
}

pub const Speed = struct {
    /// Bytes per second.
    sent: u64 = 0,
    recv: u64 = 0,
};

/// One Flow's or Row's byte history. Per-bucket counts are u32: 4 GB inside a
/// single 100 ms bucket is ~42 GB/s, past any hardware this runs on, and the
/// saturating add keeps even that from wrapping into a nonsense speed.
pub const Ring = struct {
    sent: [bucket_count]u32 = @splat(0),
    recv: [bucket_count]u32 = @splat(0),
    /// Absolute index (event ms / 100) of the newest bucket recorded. Slots
    /// for buckets the ring no longer holds are stale and never read —
    /// `advance` clears them as time passes over them.
    newest: u64 = 0,

    /// Bucket `sent`/`recv` bytes at event time `at_ms`.
    pub fn add(self: *Ring, at_ms: u64, sent: u64, recv: u64) void {
        const bucket = at_ms / bucket_ms;
        if (bucket > self.newest) self.advance(bucket);
        // Later than 1.6 s: the rate skips it, the totals already have it.
        if (!self.holds(bucket)) return;
        const i: usize = @intCast(bucket % bucket_count);
        self.sent[i] +|= std.math.lossyCast(u32, sent);
        self.recv[i] +|= std.math.lossyCast(u32, recv);
    }

    /// Bytes per second over the last full second of *settled* buckets.
    ///
    /// The window ends at the newest complete bucket the ring has data for,
    /// and may sit up to `slack_buckets` behind `now_ms` waiting for one —
    /// that lag is what makes a flush-delivered second read as the second it
    /// was. Past the slack the window moves on regardless, so a Flow that
    /// stops decays to zero within the ring's span rather than holding its
    /// last speed forever. Buckets the ring never covered count as the
    /// zeroes they are.
    pub fn speed(self: *const Ring, now_ms: u64) Speed {
        const now_bucket = now_ms / bucket_ms;
        if (now_bucket == 0) return .{};
        const end = @min(now_bucket - 1, @max(self.newest, now_bucket -| slack_buckets));
        const start = end -| (window_buckets - 1);

        var sent: u64 = 0;
        var recv: u64 = 0;
        var bucket = start;
        while (bucket <= end) : (bucket += 1) {
            if (!self.holds(bucket)) continue;
            const i: usize = @intCast(bucket % bucket_count);
            sent += self.sent[i];
            recv += self.recv[i];
        }
        // A window truncated at time zero spans less than a second; scale by
        // what it actually covers so the first second reads true.
        const span_ms = (end - start + 1) * bucket_ms;
        return .{
            .sent = sent * std.time.ms_per_s / span_ms,
            .recv = recv * std.time.ms_per_s / span_ms,
        };
    }

    /// Whether `bucket`'s slot holds that bucket's bytes: everything from the
    /// newest bucket back through the ring's span. Ahead of the newest is a
    /// bucket nothing has been written to yet; behind the span is a slot time
    /// has already passed over.
    fn holds(self: *const Ring, bucket: u64) bool {
        return bucket <= self.newest and bucket + bucket_count > self.newest;
    }

    /// Move the newest bucket forward, zeroing every slot time just passed
    /// over so their previous occupants cannot be read as current bytes.
    fn advance(self: *Ring, bucket: u64) void {
        if (bucket - self.newest >= bucket_count) {
            self.sent = @splat(0);
            self.recv = @splat(0);
        } else {
            var b = self.newest + 1;
            while (b <= bucket) : (b += 1) {
                const i: usize = @intCast(b % bucket_count);
                self.sent[i] = 0;
                self.recv[i] = 0;
            }
        }
        self.newest = bucket;
    }
};
