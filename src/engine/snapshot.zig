//! Refcounted, arena-backed immutable Snapshots (ADR-0002; CONTEXT.md
//! "Snapshot"): the Engine's only window to the outside. Each Snapshot owns
//! one arena holding itself, its rows, and its flows; publish swaps a pointer
//! under a lock that is never taken on the per-event hot path; readers
//! retain/release. A held reader's view can never change — the Engine only
//! ever builds new arenas.

const std = @import("std");
const event = @import("event.zig");
const hostnames = @import("hostnames.zig");
const sync = @import("sync.zig");

/// One Flow as published: identity, Generation, totals, whether it is riding
/// out its Linger window (dimmed in the UI), and its remote name. Service
/// attribution is a later ticket — the field is part of the v1 shape but
/// stays unpopulated here.
pub const Flow = struct {
    proto: event.Proto,
    family: event.Family,
    /// Raw network-order bytes; v4 occupies the first 4 bytes, rest zero.
    local_addr: [16]u8,
    remote_addr: [16]u8,
    /// Host byte order.
    local_port: u16,
    remote_port: u16,
    /// Distinguishes successive Flows reusing the same endpoints
    /// (CONTEXT.md "Generation"); starts at 1 per key.
    generation: u32,
    sent: u64 = 0,
    recv: u64 = 0,
    /// Closed but still visible, dimmed (CONTEXT.md "Linger").
    lingering: bool = false,
    /// The name resolved once at Flow creation and stored (CONTEXT.md
    /// "Hostname Attribution"); null shows the bare endpoint. Arena-owned by
    /// this Snapshot.
    remote_hostname: ?[]const u8 = null,
    /// The CNAME chain's tail behind `remote_hostname`, when the answer had
    /// one — the name the address actually belongs to.
    remote_alias: ?[]const u8 = null,
    /// Which tier produced `remote_hostname`. Only `observed` is the name the
    /// process actually resolved; hints render dimmed with their own marker.
    hostname_origin: hostnames.Origin = .observed,
    service: ?[]const u8 = null,
};

/// One Process Row: a process instance's identity, In-session Totals, its
/// Flows, and current connection counts. Exited rows persist all session,
/// so several rows may share a PID (at most one of them live).
pub const Row = struct {
    pid: u32,
    /// Display image path (drive-letter converted; bare name for
    /// kernel/minimal processes). Empty until a start/rundown event names
    /// the process. Arena-owned by this Snapshot.
    name: []const u8 = "",
    /// Dimmed "(exited)" in the UI; totals stay intact.
    exited: bool = false,
    sent: u64 = 0,
    recv: u64 = 0,
    /// Live (non-Lingering) flow counts by protocol.
    tcp_conns: u32 = 0,
    udp_socks: u32 = 0,
    /// This row's Flows, live and Lingering — a slice of Snapshot.flows.
    flows: []const Flow = &.{},
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
    /// Sorted by pid ascending (exited instances before a reused PID's live
    /// successor).
    rows: []const Row,
    /// All flows, grouped by owning row — each Row's `flows` is a sub-slice.
    flows: []const Flow,

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

/// Testing/Core helper: an empty Snapshot shell in its own arena. `rows` and
/// `flows` must be filled from the same arena before publish.
pub fn create(
    gpa: std.mem.Allocator,
    row_count: usize,
    flow_count: usize,
) error{OutOfMemory}!*Snapshot {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const rows = try arena.allocator().alloc(Row, row_count);
    const flow_slice = try arena.allocator().alloc(Flow, flow_count);
    const snap = try arena.allocator().create(Snapshot);
    snap.* = .{
        .refs = .init(1),
        // Captured after the last arena allocation, or teardown leaks.
        .arena_state = arena.state,
        .gpa = gpa,
        .seq = 0,
        .health = .{},
        .rows = rows,
        .flows = flow_slice,
    };
    return snap;
}

/// The arena-backed rows are mutable only between create and publish.
pub fn mutableRows(snap: *Snapshot) []Row {
    return @constCast(snap.rows);
}

/// Same publish-window mutability for the flat flow array.
pub fn mutableFlows(snap: *Snapshot) []Flow {
    return @constCast(snap.flows);
}

/// Copy `bytes` (e.g. a row's display name) into the Snapshot's own arena so
/// the row data stays self-contained. Valid only between create and publish;
/// the arena state is re-captured so release() frees these too.
pub fn arenaDupe(snap: *Snapshot, bytes: []const u8) error{OutOfMemory}![]const u8 {
    var arena = snap.arena_state.promote(snap.gpa);
    defer snap.arena_state = arena.state;
    return arena.allocator().dupe(u8, bytes);
}

test "release frees the whole arena exactly once" {
    // std.testing.allocator fails the test on leak or double-free.
    const snap = try create(std.testing.allocator, 100, 0);
    snap.retain();
    snap.release();
    snap.release();
}

test "arena-duped names live and die with the snapshot" {
    const snap = try create(std.testing.allocator, 1, 0);
    mutableRows(snap)[0] = .{
        .pid = 7,
        // Long enough to force the arena to grow a fresh buffer node.
        .name = try arenaDupe(snap, "C:\\Windows\\System32\\svchost.exe" ** 40),
    };
    try std.testing.expect(std.mem.startsWith(u8, snap.rows[0].name, "C:\\Windows"));
    snap.release(); // the allocator flags the name bytes if they leaked
}

test "publish transfers ownership and releases the replaced snapshot" {
    var published: Published = try .init();
    defer published.deinit();
    try std.testing.expectEqual(@as(?*Snapshot, null), published.acquire());

    const a = try create(std.testing.allocator, 1, 0);
    mutableRows(a)[0] = .{ .pid = 11 };
    published.publish(a);

    const held = published.acquire() orelse return error.NothingPublished;
    try std.testing.expectEqual(@as(u32, 11), held.rows[0].pid);

    // Replacing drops the slot's reference to `a`; the held one keeps it alive.
    const b = try create(std.testing.allocator, 1, 0);
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
    published.publish(try create(std.testing.allocator, 0, 0));
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, published.wake.timedWait(0));
}
