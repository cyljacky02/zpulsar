//! Bounded single-producer/single-consumer ring between the ETW consumer
//! thread and the Engine thread (ADR-0002): drop-newest on full with a loss
//! counter. No locks on the hot path — one atomic index per side. The ring
//! itself is pure; `push` reports the empty→non-empty transition so the
//! producer can set the Engine's wake event (sync.zig) exactly then.

const std = @import("std");

pub const PushResult = enum {
    /// Pushed into an empty ring — the producer must set the wake event.
    pushed_was_empty,
    pushed,
    /// Ring full; the record was dropped (drop-newest) and counted.
    dropped,
};

pub fn SpscRing(comptime T: type, comptime capacity: usize) type {
    comptime std.debug.assert(std.math.isPowerOfTwo(capacity));

    return struct {
        const Self = @This();
        const mask = capacity - 1;

        buf: [capacity]T = undefined,
        /// Consumer index; only `pop` advances it.
        head: std.atomic.Value(usize) = .init(0),
        /// Producer index; only `push` advances it.
        tail: std.atomic.Value(usize) = .init(0),
        /// Records dropped because the ring was full (drop-newest). Producer
        /// increments; the Engine reads it as the ring-loss signal.
        dropped: std.atomic.Value(u64) = .init(0),

        /// Producer side only.
        pub fn push(self: *Self, item: T) PushResult {
            const tail = self.tail.load(.monotonic);
            if (tail -% self.head.load(.acquire) == capacity) {
                _ = self.dropped.fetchAdd(1, .monotonic);
                return .dropped;
            }
            self.buf[tail & mask] = item;
            self.tail.store(tail +% 1, .release);
            // The emptiness check must re-read head *after* publishing: if the
            // consumer drained to empty concurrently, head has caught up to
            // the old tail and the transition is reported; a stale pre-push
            // head could miss it and leave the consumer sleeping on a
            // non-empty ring.
            if (self.head.load(.acquire) == tail) return .pushed_was_empty;
            return .pushed;
        }

        /// Consumer side only.
        pub fn pop(self: *Self) ?T {
            const head = self.head.load(.monotonic);
            const tail = self.tail.load(.acquire);
            if (head == tail) return null;
            const item = self.buf[head & mask];
            self.head.store(head +% 1, .release);
            return item;
        }

        pub fn isEmpty(self: *Self) bool {
            return self.head.load(.acquire) == self.tail.load(.acquire);
        }

        /// Cumulative drop-newest count; monotonic for the session.
        pub fn droppedTotal(self: *Self) u64 {
            return self.dropped.load(.monotonic);
        }
    };
}

test "fifo order across wraparound" {
    var ring: SpscRing(u32, 4) = .{};
    var next_push: u32 = 0;
    var next_pop: u32 = 0;
    for (0..3) |_| {
        // The value that fails when full stays in next_push for the next cycle.
        while (ring.push(next_push) != .dropped) next_push += 1;
        while (ring.pop()) |v| {
            try std.testing.expectEqual(next_pop, v);
            next_pop += 1;
        }
    }
    try std.testing.expectEqual(next_push, next_pop);
}

test "full ring drops newest and counts the loss" {
    var ring: SpscRing(u32, 2) = .{};
    try std.testing.expectEqual(PushResult.pushed_was_empty, ring.push(1));
    try std.testing.expectEqual(PushResult.pushed, ring.push(2));
    try std.testing.expectEqual(PushResult.dropped, ring.push(3));
    try std.testing.expectEqual(PushResult.dropped, ring.push(4));
    try std.testing.expectEqual(@as(u64, 2), ring.droppedTotal());
    // Drop-newest: the oldest records survive.
    try std.testing.expectEqual(@as(u32, 1), ring.pop().?);
    try std.testing.expectEqual(@as(u32, 2), ring.pop().?);
    try std.testing.expectEqual(@as(?u32, null), ring.pop());
}

test "push reports exactly the empty-to-nonempty transitions" {
    var ring: SpscRing(u32, 4) = .{};
    try std.testing.expectEqual(PushResult.pushed_was_empty, ring.push(1));
    try std.testing.expectEqual(PushResult.pushed, ring.push(2));
    _ = ring.pop();
    try std.testing.expectEqual(PushResult.pushed, ring.push(3)); // still non-empty
    _ = ring.pop();
    _ = ring.pop();
    try std.testing.expectEqual(@as(?u32, null), ring.pop());
    try std.testing.expectEqual(PushResult.pushed_was_empty, ring.push(4));
}

test "threaded stress: every record is either delivered in order or counted dropped" {
    const total: u32 = 100_000;
    const Ring = SpscRing(u32, 64);
    var ring: Ring = .{};

    const Producer = struct {
        fn run(r: *Ring) void {
            var i: u32 = 0;
            while (i < total) : (i += 1) _ = r.push(i);
        }
    };
    const t = try std.Thread.spawn(.{}, Producer.run, .{&ring});

    var received: u64 = 0;
    var last: ?u32 = null;
    while (received + ring.droppedTotal() < total or !ring.isEmpty()) {
        while (ring.pop()) |v| {
            if (last) |l| try std.testing.expect(v > l);
            last = v;
            received += 1;
        }
    }
    t.join();
    try std.testing.expectEqual(@as(u64, total), received + ring.droppedTotal());
}
