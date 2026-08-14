//! Refcounted, arena-backed immutable Snapshots (ADR-0002; CONTEXT.md
//! "Snapshot"): the Engine's only window to the outside. Each Snapshot owns
//! one arena holding itself and its rows; publish swaps a pointer under a
//! lock that is never taken on the per-event hot path; readers retain/release.
//! A held reader's view can never change — the Engine only ever builds new
//! arenas.

const std = @import("std");
const sync = @import("sync.zig");

/// One monitored PID's In-session Totals plus its current connection counts.
pub const Row = struct {
    pid: u32,
    sent: u64 = 0,
    recv: u64 = 0,
    tcp_conns: u32 = 0,
    udp_socks: u32 = 0,
};

pub const Health = struct {
    /// Sticky for the session once any loss occurred: totals were
    /// re-baselined and may undercount — honest or marked, never silently
    /// low (spec issue #18).
    rebaselined: bool = false,
    /// Cumulative records dropped at the SPSC ring (drop-newest).
    ring_dropped: u64 = 0,
    /// Cumulative EventsLost reported by the ETW session.
    etw_events_lost: u64 = 0,
};

pub const Snapshot = struct {
    refs: std.atomic.Value(u32),
    arena_state: std.heap.ArenaAllocator.State,
    gpa: std.mem.Allocator,
    /// Monotonic publish sequence number.
    seq: u64,
    health: Health,
    /// Sorted by pid ascending.
    rows: []const Row,

    pub fn retain(self: *Snapshot) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Snapshot) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            self.arena_state.promote(self.gpa).deinit();
        }
    }
};

/// The publish slot: pointer swap under an SRWLOCK plus the reader wake
/// event. The lock makes swap-vs-retain atomic; it is held for a few loads,
/// at publish cadence (~tick) and reader cadence (~frame) only.
pub const Published = struct {
    lock: sync.Lock = .{},
    current: ?*Snapshot = null,
    wake: sync.WakeEvent,

    pub fn init() error{EventCreateFailed}!Published {
        return .{ .wake = try sync.WakeEvent.init() };
    }

    pub fn deinit(self: *Published) void {
        if (self.current) |s| s.release();
        self.current = null;
        self.wake.deinit();
    }

    /// Takes ownership of `snap`'s initial reference and wakes readers.
    pub fn publish(self: *Published, snap: *Snapshot) void {
        self.lock.lock();
        const old = self.current;
        self.current = snap;
        self.lock.unlock();
        if (old) |o| o.release();
        self.wake.set();
    }

    /// Caller must release() the returned Snapshot.
    pub fn acquire(self: *Published) ?*Snapshot {
        self.lock.lock();
        defer self.lock.unlock();
        const s = self.current orelse return null;
        s.retain();
        return s;
    }
};

/// Testing/Core helper: an empty Snapshot shell in its own arena. `rows`
/// must be filled from the same arena before publish.
pub fn create(gpa: std.mem.Allocator, row_count: usize) error{OutOfMemory}!*Snapshot {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const rows = try arena.allocator().alloc(Row, row_count);
    const snap = try arena.allocator().create(Snapshot);
    snap.* = .{
        .refs = .init(1),
        // Captured after the last arena allocation, or teardown leaks.
        .arena_state = arena.state,
        .gpa = gpa,
        .seq = 0,
        .health = .{},
        .rows = rows,
    };
    return snap;
}

/// The arena-backed rows are mutable only between create and publish.
pub fn mutableRows(snap: *Snapshot) []Row {
    return @constCast(snap.rows);
}

test "release frees the whole arena exactly once" {
    // std.testing.allocator fails the test on leak or double-free.
    const snap = try create(std.testing.allocator, 100);
    snap.retain();
    snap.release();
    snap.release();
}

test "publish transfers ownership and releases the replaced snapshot" {
    var published: Published = try .init();
    defer published.deinit();
    try std.testing.expectEqual(@as(?*Snapshot, null), published.acquire());

    const a = try create(std.testing.allocator, 1);
    mutableRows(a)[0] = .{ .pid = 11 };
    published.publish(a);

    const held = published.acquire() orelse return error.NothingPublished;
    try std.testing.expectEqual(@as(u32, 11), held.rows[0].pid);

    // Replacing drops the slot's reference to `a`; the held one keeps it alive.
    const b = try create(std.testing.allocator, 1);
    mutableRows(b)[0] = .{ .pid = 22 };
    published.publish(b);
    try std.testing.expectEqual(@as(u32, 11), held.rows[0].pid);
    held.release();
    // `b` is released by deinit; the allocator flags anything unbalanced.
}

test "publish sets the reader wake event" {
    var published: Published = try .init();
    defer published.deinit();
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.timeout, published.wake.timedWait(0));
    published.publish(try create(std.testing.allocator, 0));
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, published.wake.timedWait(0));
}
