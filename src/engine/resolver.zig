//! The metadata resolver lane (ADR-0002 thread 4): the blocking lookups
//! Service Attribution needs — the SCM enumeration and per-socket owner-module
//! calls — run here, never on the Engine thread. `netstat -b`, the in-box
//! consumer of the same machinery, is documented as "time-consuming"; that
//! cost is exactly why it is off the hot path.
//!
//! The Engine's side of the lane is non-blocking in both directions: requests
//! go into a bounded ring (drop-newest, counted), completions come out of
//! another. A resolver call that never returns therefore costs the affected
//! Flows their service label and nothing else — event processing and Snapshot
//! publishing never wait on it.

const std = @import("std");
const flows = @import("flows.zig");
const owner_module = @import("owner_module.zig");
const service_map = @import("service_map.zig");
const sync = @import("sync.zig");

/// Which socket to resolve, and enough identity to hand the answer back to the
/// Flow that asked — or to discard it if that Flow is gone.
pub const OwnerQuery = struct {
    key: flows.FlowKey,
    /// The Flow's Generation: endpoints get reused, and an answer about the
    /// previous connection must never land on its successor.
    generation: u32,
    /// Payload CreateTime of the owning process instance. A table row whose
    /// context bind predates it describes a previous holder of the PID
    /// (research §5 case 4).
    create_time: u64,
};

/// Work for the lane. `service_map` refreshes the PID → hosted-services map.
pub const Request = union(enum) {
    service_map,
    owner_module: OwnerQuery,
};

/// A finished lookup, drained by the Engine thread. Payloads are owned by the
/// receiver.
pub const Completion = union(enum) {
    /// A fresh SCM enumeration, or null when the query failed — the Engine
    /// keeps whatever map it already had.
    service_map: ?*service_map.Raw,
    owner_module: OwnerResult,

    /// Release any payload the Engine never took ownership of (a completion
    /// dropped on a full ring, or one arriving during shutdown).
    pub fn deinit(self: Completion, gpa: std.mem.Allocator) void {
        switch (self) {
            .service_map => |raw| if (raw) |r| r.deinit(gpa),
            .owner_module => |r| if (r.module) |m| gpa.free(m),
        }
    }
};

pub const OwnerResult = struct {
    key: flows.FlowKey,
    generation: u32,
    /// The owner module name, owned by the receiver — documented as possibly
    /// "a process name, such as 'svchost.exe', a service name (such as
    /// 'RPC'), or a component name, such as 'timer.dll'". Deciding which of
    /// those it is belongs to the Engine, which holds the service map. Null
    /// when the socket has no resolvable owner at all.
    module: ?[]u8,
};

/// Where the lane's answers actually come from. Behind a vtable so the lane
/// can be driven by lookups that stall on purpose — proving that a wedged
/// lookup costs Flows their label and nothing else.
pub const Lookups = struct {
    ctx: ?*anyopaque = null,
    queryServiceMap: *const fn (ctx: ?*anyopaque, gpa: std.mem.Allocator) ?*service_map.Raw,
    /// Resolves a whole batch: `out[i]` is the owned module name for
    /// `queries[i]`, or null. Batching lets one table snapshot serve every
    /// query in it.
    resolveOwners: *const fn (
        ctx: ?*anyopaque,
        gpa: std.mem.Allocator,
        queries: []const OwnerQuery,
        out: []?[]u8,
    ) void,
};

/// The real Windows lookups.
pub const system_lookups: Lookups = .{
    .queryServiceMap = systemQueryServiceMap,
    .resolveOwners = systemResolveOwners,
};

fn systemQueryServiceMap(_: ?*anyopaque, gpa: std.mem.Allocator) ?*service_map.Raw {
    return service_map.query(gpa);
}

fn systemResolveOwners(
    _: ?*anyopaque,
    gpa: std.mem.Allocator,
    queries: []const OwnerQuery,
    out: []?[]u8,
) void {
    owner_module.resolveAll(gpa, queries, out);
}

/// How many requests may be in flight. Past this, new work is dropped rather
/// than queued: a label that arrives after its Flow is long gone is worth
/// less than a bounded queue.
pub const request_capacity = 256;
/// Answers waiting for the Engine to drain them. Twice the request ring, so
/// an Engine pass that lands mid-batch has room.
pub const completion_capacity = 512;

/// A fixed-capacity FIFO. Both directions of the lane are bounded by
/// construction — nothing here allocates.
///
/// Not `spsc_ring.zig`: that one is lock-free because it sits on the
/// per-event hot path, and pays for it by supporting only blind pushes. This
/// lane is off the hot path (one wake per batch, at most a few per second),
/// and needs the lock anyway to coalesce duplicate service-map requests and
/// to free the payload of a completion it had to drop — neither of which a
/// lock-free push can express.
fn Ring(comptime T: type, comptime capacity: usize) type {
    return struct {
        items: [capacity]T = undefined,
        head: usize = 0,
        len: usize = 0,

        fn push(self: *@This(), value: T) bool {
            if (self.len == capacity) return false;
            self.items[(self.head + self.len) % capacity] = value;
            self.len += 1;
            return true;
        }

        fn pop(self: *@This()) ?T {
            if (self.len == 0) return null;
            const value = self.items[self.head];
            self.head = (self.head + 1) % capacity;
            self.len -= 1;
            return value;
        }
    };
}

/// The lane: one thread, two bounded queues, no blocking on the Engine's
/// side. Large enough to want heap placement — `runner.zig` creates it and
/// calls `init` in place.
pub const Lane = struct {
    gpa: std.mem.Allocator,
    lookups: Lookups,
    /// Guards both rings and the flags. Held for pushes and pops only, never
    /// across a lookup.
    lock: sync.Lock = .{},
    /// Signals the lane thread that there is work (or that it should stop).
    wake: sync.WakeEvent,
    /// Set once `run` has returned for good, so shutdown can bound its wait
    /// rather than hang behind a wedged lookup (ADR-0002).
    exited: sync.WakeEvent,
    requests: Ring(Request, request_capacity) = .{},
    completions: Ring(Completion, completion_capacity) = .{},
    /// A service-map refresh is already queued; another would enumerate the
    /// same SCM twice.
    map_queued: bool = false,
    stopping: bool = false,
    dropped: u64 = 0,
    /// Signalled whenever an answer is ready, so the Engine thread wakes to
    /// apply it instead of waiting out its flush tick — that difference is
    /// most of the Attribution Latency budget.
    completion_wake: ?sync.WakeEvent = null,

    pub fn init(self: *Lane, gpa: std.mem.Allocator, lookups: Lookups) error{EventCreateFailed}!void {
        const wake = try sync.WakeEvent.init();
        errdefer wake.deinit();
        const exited = try sync.WakeEvent.init();
        self.* = .{ .gpa = gpa, .lookups = lookups, .wake = wake, .exited = exited };
    }

    /// Wake `event` whenever an answer lands. Must be called before the lane
    /// thread starts, and the event must outlive the thread — including a
    /// thread abandoned at shutdown, which can still signal it.
    pub fn wakeOnCompletion(self: *Lane, event: sync.WakeEvent) void {
        self.completion_wake = event;
    }

    /// Only safe once the lane thread is known to be gone — anything it left
    /// undrained is freed here.
    pub fn deinit(self: *Lane) void {
        while (self.completions.pop()) |c| c.deinit(self.gpa);
        self.wake.deinit();
        self.exited.deinit();
    }

    /// Engine thread: post work. False when the ring is full (counted in
    /// `dropped`) — the caller falls back rather than retrying.
    pub fn submit(self: *Lane, req: Request) bool {
        self.lock.lock();
        if (req == .service_map and self.map_queued) {
            self.lock.unlock();
            return true; // already queued: the same answer serves both
        }
        if (!self.requests.push(req)) {
            self.dropped += 1;
            self.lock.unlock();
            return false;
        }
        if (req == .service_map) self.map_queued = true;
        self.lock.unlock();
        self.wake.set();
        return true;
    }

    /// Engine thread: take one finished lookup, or null. Never blocks — this
    /// is what keeps a wedged lane off the Engine's critical path.
    pub fn nextCompletion(self: *Lane) ?Completion {
        self.lock.lock();
        defer self.lock.unlock();
        return self.completions.pop();
    }

    /// Ask the lane thread to finish. It stops between lookups, so a call
    /// already in progress still has to return on its own — see `waitExit`.
    pub fn shutdown(self: *Lane) void {
        self.lock.lock();
        self.stopping = true;
        self.lock.unlock();
        self.wake.set();
    }

    /// True if the lane thread has left `run`. False means it is still inside
    /// a lookup and the caller must abandon it rather than wait forever.
    pub fn waitExit(self: *Lane, timeout_ms: u32) bool {
        return self.exited.timedWait(timeout_ms) == .signaled;
    }

    /// The lane thread's whole life.
    pub fn run(self: *Lane) void {
        var batch: [request_capacity]Request = undefined;
        while (true) {
            const n = self.take(&batch);
            if (n == 0) {
                // No lost wakeup: `shutdown` sets the flag before signalling,
                // and the event latches until a wait consumes it.
                if (self.stopRequested()) break;
                _ = self.wake.timedWait(std.math.maxInt(u32));
                continue;
            }
            self.process(batch[0..n]);
        }
        self.exited.set();
    }

    fn take(self: *Lane, batch: []Request) usize {
        self.lock.lock();
        defer self.lock.unlock();
        var n: usize = 0;
        while (n < batch.len) : (n += 1) {
            const req = self.requests.pop() orelse break;
            if (req == .service_map) self.map_queued = false;
            batch[n] = req;
        }
        return n;
    }

    fn stopRequested(self: *Lane) bool {
        self.lock.lock();
        defer self.lock.unlock();
        return self.stopping;
    }

    /// One batch of lookups, run outside the lock. The owner-module queries
    /// go together so they share a single table snapshot.
    fn process(self: *Lane, batch: []const Request) void {
        var queries: [request_capacity]OwnerQuery = undefined;
        var modules: [request_capacity]?[]u8 = undefined;
        var n: usize = 0;
        for (batch) |req| switch (req) {
            .service_map => self.complete(.{
                .service_map = self.lookups.queryServiceMap(self.lookups.ctx, self.gpa),
            }),
            .owner_module => |q| {
                queries[n] = q;
                n += 1;
            },
        };
        if (n == 0) return;
        @memset(modules[0..n], null);
        self.lookups.resolveOwners(self.lookups.ctx, self.gpa, queries[0..n], modules[0..n]);
        for (queries[0..n], modules[0..n]) |q, module| self.complete(.{ .owner_module = .{
            .key = q.key,
            .generation = q.generation,
            .module = module,
        } });
    }

    /// Hand an answer back. An Engine that has stopped draining loses the
    /// answer rather than the lane — the payload is freed here.
    fn complete(self: *Lane, completion: Completion) void {
        self.lock.lock();
        const queued = self.completions.push(completion);
        if (!queued) self.dropped += 1;
        self.lock.unlock();
        if (!queued) {
            completion.deinit(self.gpa);
            return;
        }
        if (self.completion_wake) |wake| wake.set();
    }
};

// ---------------------------------------------------------------------------
// Tests — the lane driven by fake backends, including one that stalls on
// purpose. The real lookups need a live machine and run in the headless rig.
// ---------------------------------------------------------------------------

/// Lookups the test drives: they can answer, and they can hang until released.
const FakeLookups = struct {
    gpa: std.mem.Allocator,
    /// While set, every lookup hangs — for as many lookups as the test makes,
    /// not just the first.
    stalling: std.atomic.Value(bool) = .init(false),
    /// Set the moment a lookup starts, so a test can wait for the stall to
    /// actually be underway instead of sleeping.
    entered: sync.WakeEvent,
    maps: std.atomic.Value(u32) = .init(0),

    fn init(gpa: std.mem.Allocator) error{EventCreateFailed}!FakeLookups {
        return .{ .gpa = gpa, .entered = try .init() };
    }

    fn deinit(self: *FakeLookups) void {
        self.entered.deinit();
    }

    fn lookups(self: *FakeLookups) Lookups {
        return .{
            .ctx = self,
            .queryServiceMap = queryServiceMap,
            .resolveOwners = resolveOwners,
        };
    }

    fn stall(self: *FakeLookups) void {
        self.stalling.store(true, .release);
    }

    fn release(self: *FakeLookups) void {
        self.stalling.store(false, .release);
    }

    fn hold(self: *FakeLookups) void {
        self.entered.set();
        while (self.stalling.load(.acquire)) std.Thread.yield() catch {};
    }

    fn queryServiceMap(ctx: ?*anyopaque, gpa: std.mem.Allocator) ?*service_map.Raw {
        const self: *FakeLookups = @ptrCast(@alignCast(ctx.?));
        self.hold();
        _ = self.maps.fetchAdd(1, .monotonic);
        return service_map.fromPairs(gpa, 200, &.{.{ .pid = 900, .name = "RpcSs" }}) catch null;
    }

    fn resolveOwners(
        ctx: ?*anyopaque,
        gpa: std.mem.Allocator,
        queries: []const OwnerQuery,
        out: []?[]u8,
    ) void {
        const self: *FakeLookups = @ptrCast(@alignCast(ctx.?));
        self.hold();
        for (queries, out) |q, *slot| {
            // Echo the port back so a test can tell the answers apart.
            var buf: [16]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "svc{d}", .{q.key.tuple.local_port}) catch return;
            slot.* = gpa.dupe(u8, text) catch null;
        }
    }
};

fn testOwnerQuery(local_port: u16) OwnerQuery {
    return .{
        .generation = 1,
        .create_time = 100,
        .key = .{ .pid = 900, .tuple = .{
            .proto = .tcp,
            .family = .v4,
            .local_addr = @splat(0),
            .remote_addr = @splat(0),
            .local_port = local_port,
            .remote_port = 443,
        } },
    };
}

test "a submitted lookup comes back as a completion" {
    const gpa = std.testing.allocator;
    var fake = try FakeLookups.init(gpa);
    defer fake.deinit();

    var lane: Lane = undefined;
    try lane.init(gpa, fake.lookups());
    defer lane.deinit();
    const thread = try std.Thread.spawn(.{}, Lane.run, .{&lane});

    try std.testing.expect(lane.submit(.{ .owner_module = testOwnerQuery(51000) }));
    var answer: ?Completion = null;
    while (answer == null) answer = lane.nextCompletion();
    defer answer.?.deinit(gpa);

    lane.shutdown();
    thread.join();

    try std.testing.expectEqualStrings("svc51000", answer.?.owner_module.module.?);
    try std.testing.expectEqual(@as(u16, 51000), answer.?.owner_module.key.tuple.local_port);
}

test "a stalled lookup never blocks the Engine's side of the lane" {
    const gpa = std.testing.allocator;
    var fake = try FakeLookups.init(gpa);
    defer fake.deinit();
    fake.stall();

    var lane: Lane = undefined;
    try lane.init(gpa, fake.lookups());
    defer lane.deinit();
    const thread = try std.Thread.spawn(.{}, Lane.run, .{&lane});

    try std.testing.expect(lane.submit(.service_map));
    // Wait for the lookup to actually be wedged, then keep using the lane.
    try std.testing.expectEqual(sync.WakeEvent.WaitResult.signaled, fake.entered.timedWait(5_000));

    // Both Engine-side calls return immediately, over and over, while the
    // lane thread is stuck inside a lookup.
    for (0..1000) |i| {
        _ = lane.submit(.{ .owner_module = testOwnerQuery(@intCast(50_000 + i % 100)) });
        try std.testing.expectEqual(@as(?Completion, null), lane.nextCompletion());
    }
    // Past the ring's capacity, the excess was dropped rather than queued.
    try std.testing.expect(lane.dropped > 0);

    fake.release(); // let the wedged lookups finish so the thread can exit
    lane.shutdown();
    thread.join();
    try std.testing.expect(lane.waitExit(0));
}

test "duplicate service-map requests coalesce into one enumeration" {
    const gpa = std.testing.allocator;
    var fake = try FakeLookups.init(gpa);
    defer fake.deinit();

    var lane: Lane = undefined;
    try lane.init(gpa, fake.lookups());
    defer lane.deinit();

    // No thread yet: queue the duplicates first, so they are certain to be
    // in the ring together rather than racing the lane's drain.
    for (0..8) |_| try std.testing.expect(lane.submit(.service_map));
    try std.testing.expectEqual(@as(usize, 1), lane.requests.len);

    const thread = try std.Thread.spawn(.{}, Lane.run, .{&lane});
    var answer: ?Completion = null;
    while (answer == null) answer = lane.nextCompletion();
    answer.?.deinit(gpa);
    lane.shutdown();
    thread.join();
    try std.testing.expectEqual(@as(u32, 1), fake.maps.load(.monotonic));
}

test "answers the Engine never drained are freed with the lane" {
    const gpa = std.testing.allocator;
    var fake = try FakeLookups.init(gpa);
    defer fake.deinit();

    var lane: Lane = undefined;
    try lane.init(gpa, fake.lookups());
    const thread = try std.Thread.spawn(.{}, Lane.run, .{&lane});
    try std.testing.expect(lane.submit(.service_map));
    try std.testing.expect(lane.submit(.{ .owner_module = testOwnerQuery(51000) }));
    lane.shutdown();
    thread.join();

    // Nothing was ever drained; deinit owns what is left. The testing
    // allocator fails this test if either payload leaks.
    lane.deinit();
}
