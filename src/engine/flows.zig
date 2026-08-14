//! The Flow layer (issue #22; CONTEXT.md "Flow", "Generation", "Linger"):
//! per-Flow identity, lifecycle, and totals inside the Engine thread's
//! single-threaded state. Flows are keyed (protocol, local endpoint, remote
//! endpoint, owning PID); endpoint reuse after closure starts a new
//! Generation — never resuming the old Flow or its totals. Each Flow binds
//! to its owning Process Row instance (core.zig row index) when it opens and
//! never migrates. Closed Flows Linger 10 s and then leave the list; their
//! bytes live on in the Process Row totals, which are independent
//! accumulators (core.zig), never a sum of visible flows.

const std = @import("std");
const event = @import("event.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

/// Closed Flows stay visible, dimmed, this long (spec issue #18 Data model).
pub const linger_ms: u64 = 10_000;
/// UDP Flows age out after this much inactivity — no lifecycle events exist.
pub const udp_idle_ms: u64 = 60_000;

/// Flow identity (spec: protocol, local endpoint, remote endpoint, owning
/// PID). Unlike the table-dedupe ConnKey, UDP keeps its real remote endpoint:
/// one socket talking to N remotes is N Flows.
pub const FlowKey = struct {
    tuple: event.ConnKey,
    pid: u32,
};

pub fn flowKey(ev: event.NetEvent) FlowKey {
    return .{ .pid = ev.pid, .tuple = .{
        .proto = ev.proto,
        .family = ev.family,
        .local_addr = ev.local_addr,
        .remote_addr = ev.remote_addr,
        .local_port = ev.local_port,
        .remote_port = ev.remote_port,
    } };
}

/// How far Service Attribution (issue #25) has got with a Flow. The Flow
/// layer only stores this; which tier applies is core.zig's decision.
pub const Resolution = enum {
    /// No service map has covered the owning process instance yet.
    unclassified,
    /// A per-socket owner-module lookup is in flight on the resolver lane.
    pending,
    /// Nothing more will be asked: the answer landed, failed, or was never
    /// needed (the map alone settles single-service and non-service hosts).
    settled,
};

pub const Live = struct {
    generation: u32,
    /// Owning Process Row instance (core.zig row index), bound at open —
    /// a Flow never migrates between Process Rows.
    row: u32,
    sent: u64 = 0,
    recv: u64 = 0,
    last_activity_ms: u64,
    resolution: Resolution = .unclassified,
    /// The service that owns this socket, resolved per-socket (tier 2).
    /// Interned by core.zig, so it outlives every service map.
    service: ?[]const u8 = null,
};

/// One key's history: the current live Flow (if any), how many closed
/// generations still Linger, and the last Generation number handed out. The
/// slot leaves the map only when nothing under the key is visible anymore.
const Slot = struct {
    last_gen: u32 = 0,
    live: ?Live = null,
    linger_count: u32 = 0,
};

/// A closed Flow riding out its Linger window. Totals are frozen at close.
const Lingering = struct {
    key: FlowKey,
    generation: u32,
    row: u32,
    sent: u64,
    recv: u64,
    expires_at_ms: u64,
    /// Carried over from the live Flow: a closed Flow keeps its label for the
    /// window it stays visible, and a late answer can still land on it.
    service: ?[]const u8 = null,
};

fn isZeroRemote(tuple: event.ConnKey) bool {
    return tuple.remote_port == 0 and
        std.mem.allEqual(u8, &tuple.remote_addr, 0);
}

/// A live Flow's presence at the granularity the owner tables know: TCP by
/// full tuple, UDP collapsed to the local endpoint (event.connKey rules).
fn presenceTuple(tuple: event.ConnKey) event.ConnKey {
    var t = tuple;
    if (t.proto == .udp) {
        t.remote_addr = @splat(0);
        t.remote_port = 0;
    }
    return t;
}

/// One Flow ready for Snapshot building, carrying its owning row index.
pub const Entry = struct {
    row: u32,
    flow: snapshot.Flow,
};

pub const Table = struct {
    slots: std.AutoHashMapUnmanaged(FlowKey, Slot) = .empty,
    /// Closed Flows in close order — monotonic time makes this expiry order.
    linger: std.ArrayList(Lingering) = .empty,
    linger_head: usize = 0,
    live_count: usize = 0,
    /// Sweep scratch, reused per sweep: the table snapshot's tuples, and the
    /// tuples still-live Flows cover.
    scratch_tuples: std.AutoHashMapUnmanaged(event.ConnKey, void) = .empty,
    scratch_live: std.AutoHashMapUnmanaged(event.ConnKey, void) = .empty,

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        self.slots.deinit(gpa);
        self.linger.deinit(gpa);
        self.scratch_tuples.deinit(gpa);
        self.scratch_live.deinit(gpa);
    }

    pub fn count(self: *const Table) usize {
        return self.live_count + (self.linger.items.len - self.linger_head);
    }

    /// Data or connect activity on a key: refresh the live Flow, or open a
    /// new Generation owned by `row` if the key has none (first activity
    /// after closure).
    pub fn touch(
        self: *Table,
        gpa: std.mem.Allocator,
        key: FlowKey,
        row: u32,
        now_ms: u64,
    ) error{OutOfMemory}!*Live {
        if (self.slots.getPtr(key)) |slot| {
            if (slot.live) |*l| {
                l.last_activity_ms = now_ms;
                return l;
            }
        }
        if (key.tuple.proto == .udp and !isZeroRemote(key.tuple))
            try self.dropUdpPlaceholder(gpa, key, now_ms);
        const gop = try self.slots.getOrPut(gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.last_gen += 1;
        gop.value_ptr.live = .{
            .generation = gop.value_ptr.last_gen,
            .row = row,
            .last_activity_ms = now_ms,
        };
        self.live_count += 1;
        return &gop.value_ptr.live.?;
    }

    /// A connect (or accept) means a new connection. On a live Flow that has
    /// carried bytes, its closure was lost and the endpoints are reused:
    /// close it and start a new Generation — totals never merge across
    /// connections. A zero-byte live Flow is the same connection seen twice
    /// (table seed racing the buffered connect) and is kept.
    pub fn connect(
        self: *Table,
        gpa: std.mem.Allocator,
        key: FlowKey,
        row: u32,
        now_ms: u64,
    ) error{OutOfMemory}!*Live {
        if (self.slots.getPtr(key)) |slot| {
            if (slot.live) |l| {
                if (l.sent + l.recv > 0) _ = try self.close(gpa, key, now_ms);
            }
        }
        return self.touch(gpa, key, row, now_ms);
    }

    /// A real per-remote conversation supersedes the socket's table-seeded
    /// zero-remote placeholder. A byte-less placeholder vanishes outright —
    /// nothing is lost; one that somehow carried bytes closes into Linger
    /// (bytes stay visible, per the eviction invariant's spirit).
    fn dropUdpPlaceholder(
        self: *Table,
        gpa: std.mem.Allocator,
        key: FlowKey,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        var placeholder = key;
        placeholder.tuple.remote_addr = @splat(0);
        placeholder.tuple.remote_port = 0;
        const slot = self.slots.getPtr(placeholder) orelse return;
        const l = slot.live orelse return;
        if (l.sent + l.recv > 0) {
            _ = try self.close(gpa, placeholder, now_ms);
            return;
        }
        slot.live = null;
        self.live_count -= 1;
        if (slot.linger_count == 0) _ = self.slots.remove(placeholder);
    }

    /// Close the key's live Flow into Linger. False if none was live.
    /// Safe to call while iterating `slots` — it never removes a slot.
    pub fn close(
        self: *Table,
        gpa: std.mem.Allocator,
        key: FlowKey,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        const slot = self.slots.getPtr(key) orelse return false;
        const l = slot.live orelse return false;
        try self.linger.append(gpa, .{
            .key = key,
            .generation = l.generation,
            .row = l.row,
            .sent = l.sent,
            .recv = l.recv,
            .expires_at_ms = now_ms + linger_ms,
            .service = l.service,
        });
        slot.live = null;
        slot.linger_count += 1;
        self.live_count -= 1;
        return true;
    }

    /// Time-driven maintenance: retire Lingering Flows whose window ended,
    /// and age idle UDP Flows out into normal Linger (no lifecycle events
    /// exist for UDP). `now_ms` must be monotonic across all Table calls.
    pub fn tick(
        self: *Table,
        gpa: std.mem.Allocator,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        var changed = false;
        while (self.linger_head < self.linger.items.len) {
            const l = self.linger.items[self.linger_head];
            if (l.expires_at_ms > now_ms) break;
            self.linger_head += 1;
            changed = true;
            const slot = self.slots.getPtr(l.key).?;
            slot.linger_count -= 1;
            if (slot.linger_count == 0 and slot.live == null)
                _ = self.slots.remove(l.key);
        }
        self.compactLinger();

        // UDP age-out. close() never removes slots, so closing while
        // iterating is safe.
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.key_ptr.tuple.proto != .udp) continue;
            const l = e.value_ptr.live orelse continue;
            if (now_ms - l.last_activity_ms >= udp_idle_ms) {
                _ = try self.close(gpa, e.key_ptr.*, now_ms);
                changed = true;
            }
        }
        return changed;
    }

    /// The queue only ever grows at the tail; reclaim the dead prefix once
    /// it dominates, so sustained churn cannot grow it without bound.
    fn compactLinger(self: *Table) void {
        if (self.linger_head == self.linger.items.len) {
            self.linger.clearRetainingCapacity();
            self.linger_head = 0;
        } else if (self.linger_head >= 64 and
            self.linger_head * 2 >= self.linger.items.len)
        {
            const remaining = self.linger.items.len - self.linger_head;
            std.mem.copyForwards(
                Lingering,
                self.linger.items[0..remaining],
                self.linger.items[self.linger_head..],
            );
            self.linger.shrinkRetainingCapacity(remaining);
            self.linger_head = 0;
        }
    }

    /// Reconcile against a fresh IP Helper table snapshot — the cold-start
    /// seed, the 10 s sweep, and loss re-baseline are all this one motion.
    /// The tables are ground truth for existence: a live TCP Flow the table
    /// no longer shows lost its close event and is closed here (the safety
    /// net); a zero-remote UDP placeholder lives exactly as long as its
    /// socket stays bound. Per-remote UDP conversations are the tables'
    /// blind spot and age out on inactivity instead.
    ///
    /// `row_source.rowForSeed(pid)` supplies the owning Process Row for a
    /// Flow this call actually seeds — asked only then, so skipped table
    /// rows can't mint ghost placeholder rows.
    pub fn reconcile(
        self: *Table,
        gpa: std.mem.Allocator,
        rows: []const tables.SeededConn,
        row_source: anytype,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        var changed = false;
        self.scratch_tuples.clearRetainingCapacity();
        for (rows) |r| try self.scratch_tuples.put(gpa, r.key, {});
        // Close/refresh live Flows against the tables, and record what the
        // survivors cover at table granularity. The presence check is
        // PID-blind on purpose: duplicated/inherited sockets appear as
        // sibling Flows, but the table names one owner.
        self.scratch_live.clearRetainingCapacity();
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.live == null) continue;
            const tuple = e.key_ptr.tuple;
            switch (tuple.proto) {
                .tcp => if (!self.scratch_tuples.contains(tuple)) {
                    _ = try self.close(gpa, e.key_ptr.*, now_ms);
                    changed = true;
                    continue;
                },
                .udp => if (isZeroRemote(tuple)) {
                    if (self.scratch_tuples.contains(tuple)) {
                        e.value_ptr.live.?.last_activity_ms = now_ms;
                    } else {
                        _ = try self.close(gpa, e.key_ptr.*, now_ms);
                        changed = true;
                        continue;
                    }
                },
            }
            try self.scratch_live.put(gpa, presenceTuple(tuple), {});
        }
        // Seed table rows no surviving Flow covers. Half-closed rows are
        // presence only — seeding them would revive event-closed Flows as
        // ghosts. A live UDP Flow on the socket already represents it — the
        // local-only table row would double it (the seed's job is presence,
        // and presence is covered).
        for (rows) |r| {
            if (r.closing) continue;
            if (self.scratch_live.contains(r.key)) continue;
            const row = try row_source.rowForSeed(r.pid);
            _ = try self.touch(gpa, .{ .tuple = r.key, .pid = r.pid }, row, now_ms);
            try self.scratch_live.put(gpa, r.key, {});
            changed = true;
        }
        return changed;
    }

    /// A Process Row instance retired: close its live Flows into normal
    /// Linger (spec issue #18 Data model "process exit closes its live
    /// Flows immediately into normal Linger").
    pub fn closeRowFlows(
        self: *Table,
        gpa: std.mem.Allocator,
        row: u32,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        var changed = false;
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const l = e.value_ptr.live orelse continue;
            if (l.row != row) continue;
            _ = try self.close(gpa, e.key_ptr.*, now_ms);
            changed = true;
        }
        return changed;
    }

    /// Apply a per-socket resolution to one Generation. What the module name
    /// denotes is core.zig's call — it holds the service map — so this asks
    /// `ctx.serviceNamed(row, module)` once the owning row is known, then
    /// stores whatever comes back (null = no service could be named).
    ///
    /// The Flow stops asking either way: the answer is as good as it gets,
    /// and a failed lookup leaves the honest fallback standing rather than
    /// retrying against a table row that is already gone. False when the Flow
    /// no longer exists — which is how an answer nobody can see anymore is
    /// dropped.
    pub fn applyOwnerModule(
        self: *Table,
        key: FlowKey,
        generation: u32,
        module: ?[]const u8,
        ctx: anytype,
    ) bool {
        const slot = self.slots.getPtr(key) orelse return false;
        if (slot.live) |*l| {
            if (l.generation == generation) {
                l.service = if (module) |m| ctx.serviceNamed(l.row, m) else null;
                l.resolution = .settled;
                return true;
            }
        }
        // Closed while the lookup was in flight: it still shows for its
        // Linger window, so the label is still worth having.
        if (slot.linger_count == 0) return false;
        for (self.linger.items[self.linger_head..]) |*l| {
            if (l.generation == generation and std.meta.eql(l.key, key)) {
                l.service = if (module) |m| ctx.serviceNamed(l.row, m) else null;
                return true;
            }
        }
        return false;
    }

    /// Hand every live Flow still awaiting its Service Attribution tier
    /// decision to `ctx.classify(key, live)`. Run when a fresh service map
    /// lands: a Flow that opened before any map could describe its process
    /// gets its decision then.
    pub fn eachUnclassified(self: *Table, ctx: anytype) void {
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.live) |*l| {
                if (l.resolution != .unclassified) continue;
                ctx.classify(e.key_ptr.*, l);
            }
        }
    }

    /// Every visible Flow — live and Lingering — with its owning row index.
    pub fn collect(
        self: *const Table,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(Entry),
    ) error{OutOfMemory}!void {
        try out.ensureUnusedCapacity(gpa, self.count());
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const l = e.value_ptr.live orelse continue;
            out.appendAssumeCapacity(
                entry(e.key_ptr.*, l.generation, l.row, l.sent, l.recv, false, l.service),
            );
        }
        for (self.linger.items[self.linger_head..]) |l| {
            out.appendAssumeCapacity(
                entry(l.key, l.generation, l.row, l.sent, l.recv, true, l.service),
            );
        }
    }

    fn entry(
        key: FlowKey,
        generation: u32,
        row: u32,
        sent: u64,
        recv: u64,
        lingering: bool,
        service: ?[]const u8,
    ) Entry {
        return .{ .row = row, .flow = .{
            .proto = key.tuple.proto,
            .family = key.tuple.family,
            .local_addr = key.tuple.local_addr,
            .remote_addr = key.tuple.remote_addr,
            .local_port = key.tuple.local_port,
            .remote_port = key.tuple.remote_port,
            .generation = generation,
            .sent = sent,
            .recv = recv,
            .lingering = lingering,
            .service = service,
        } };
    }
};
