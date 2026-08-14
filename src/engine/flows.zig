//! The Flow layer (issue #22; CONTEXT.md "Flow", "Generation", "Linger"):
//! per-Flow identity, lifecycle, and totals inside the Engine thread's
//! single-threaded state. Flows are keyed (protocol, local endpoint, remote
//! endpoint, owning PID); endpoint reuse after closure starts a new
//! Generation — never resuming the old Flow or its totals. Each Flow binds
//! to its owning Process Row instance (core.zig row index) when it opens and
//! never migrates. Closed Flows Linger 10 s and then leave the list; their
//! bytes live on in the Process Row totals, which are independent
//! accumulators (core.zig), never a sum of visible flows. That independence
//! is what makes the Flow cap (issue #23) safe: this table holds visibility,
//! not accounting, so evicting from it can cost detail but never bytes.

const std = @import("std");
const event = @import("event.zig");
const rates = @import("rates.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

/// Closed Flows stay visible, dimmed, this long (spec issue #18 Data model).
pub const linger_ms: u64 = 10_000;
/// UDP Flows age out after this much inactivity — no lifecycle events exist.
pub const udp_idle_ms: u64 = 60_000;
/// The Flow cap (spec issue #18 Data model, "Memory bounds"): at most this
/// many visible Flows. Well past any real machine's connection count, so the
/// cap is a bound on pathology, not a working limit.
pub const cap: usize = 16 * 1024;
/// An owning Process Row that Core evicted, in a `remapRows` table.
pub const removed_row: u32 = std.math.maxInt(u32);

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

const Live = struct {
    generation: u32,
    /// Owning Process Row instance (core.zig row index), bound at open —
    /// a Flow never migrates between Process Rows.
    row: u32,
    sent: u64 = 0,
    recv: u64 = 0,
    /// Event-time byte history behind this Flow's displayed speed.
    rate: rates.Ring = .{},
    last_activity_ms: u64,
};

/// One key's history: the current live Flow (if any), how many closed
/// generations still Linger, and the last Generation number handed out. The
/// slot leaves the map only when nothing under the key is visible anymore.
const Slot = struct {
    last_gen: u32 = 0,
    live: ?Live = null,
    linger_count: u32 = 0,
};

/// A closed Flow riding out its Linger window: the Flow exactly as it stood
/// at close, frozen. Its rate ring is frozen with it, so the last bytes it
/// moved still show as speed and then decay to zero on their own. Holding
/// the whole `Live` rather than a copy of its fields means a Flow only ever
/// grows a field in one place.
const Lingering = struct {
    key: FlowKey,
    flow: Live,
    expires_at_ms: u64,
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

/// Eviction ordering for live Flows: least recently active first.
const Idle = struct {
    key: FlowKey,
    last_activity_ms: u64,
};

fn idleFirst(_: void, a: Idle, b: Idle) bool {
    return a.last_activity_ms < b.last_activity_ms;
}

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
    ) error{OutOfMemory}!void {
        if (self.slots.getPtr(key)) |slot| {
            if (slot.live) |l| {
                if (l.sent + l.recv > 0) _ = try self.close(gpa, key, now_ms);
            }
        }
        _ = try self.touch(gpa, key, row, now_ms);
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
            .flow = l,
            .expires_at_ms = now_ms + linger_ms,
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
            if (self.linger.items[self.linger_head].expires_at_ms > now_ms) break;
            self.retireOldestLingering();
            changed = true;
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

    /// Enforce the Flow cap (CONTEXT.md "Eviction"). Closed Flows go first,
    /// oldest-first: their bytes already live in their Process Row's totals,
    /// so dropping them costs visibility only. If live Flows alone still
    /// exceed the cap, the longest-idle ones go — the key leaves the table
    /// entirely, so the next activity on it opens a fresh Generation with
    /// its own totals rather than resuming what the Row already holds.
    /// Bytes are never at stake here: no accounting lives in this table.
    pub fn evict(self: *Table, gpa: std.mem.Allocator) error{OutOfMemory}!bool {
        if (self.count() <= cap) return false;

        // Closed Flows, in close order.
        while (self.count() > cap and self.linger_head < self.linger.items.len)
            self.retireOldestLingering();
        self.compactLinger();
        if (self.live_count <= cap) return true;

        // Live Flows, longest idle first. The allocation comes before any
        // live Flow is touched, so an OOM here costs nothing already done —
        // the closed Flows above stay evicted, the next tick retries.
        var idle: std.ArrayList(Idle) = .empty;
        defer idle.deinit(gpa);
        try idle.ensureTotalCapacity(gpa, self.live_count);
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const l = e.value_ptr.live orelse continue;
            idle.appendAssumeCapacity(.{
                .key = e.key_ptr.*,
                .last_activity_ms = l.last_activity_ms,
            });
        }
        std.mem.sort(Idle, idle.items, {}, idleFirst);
        const excess = self.live_count - cap;
        for (idle.items[0..excess]) |victim| {
            const slot = self.slots.getPtr(victim.key).?;
            slot.live = null;
            self.live_count -= 1;
            if (slot.linger_count == 0) _ = self.slots.remove(victim.key);
        }
        return true;
    }

    /// Drop the Linger queue's head — whether its window ended or the cap
    /// came for it — and retire the slot behind it if nothing else there is
    /// still visible. Caller must not be iterating `slots`.
    fn retireOldestLingering(self: *Table) void {
        const l = self.linger.items[self.linger_head];
        self.linger_head += 1;
        const slot = self.slots.getPtr(l.key).?;
        slot.linger_count -= 1;
        if (slot.linger_count == 0 and slot.live == null)
            _ = self.slots.remove(l.key);
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

    /// Core evicted Process Rows and renumbered the survivors (`map[old]` is
    /// the new index, or `removed_row`): drop every Flow whose owning row is
    /// gone — its bytes went up into the Evicted-processes Row with its
    /// owner — and repoint the rest. Allocation happens before any of it is
    /// applied, so a failure leaves the table untouched.
    pub fn remapRows(
        self: *Table,
        gpa: std.mem.Allocator,
        map: []const u32,
    ) error{OutOfMemory}!void {
        var dead: std.ArrayList(FlowKey) = .empty;
        defer dead.deinit(gpa);
        try dead.ensureTotalCapacity(gpa, self.slots.count());

        // The Linger queue, filtered and compacted to the front. Close order
        // — and so expiry order — is preserved by the in-place walk.
        var w: usize = 0;
        for (self.linger.items[self.linger_head..]) |l| {
            const to = map[l.flow.row];
            if (to == removed_row) continue;
            self.linger.items[w] = l;
            self.linger.items[w].flow.row = to;
            w += 1;
        }
        self.linger.shrinkRetainingCapacity(w);
        self.linger_head = 0;

        // Live Flows, and the per-slot Linger counts the filtered queue now
        // implies.
        var it = self.slots.iterator();
        while (it.next()) |e| {
            e.value_ptr.linger_count = 0;
            if (e.value_ptr.live) |*l| {
                const to = map[l.row];
                if (to == removed_row) {
                    e.value_ptr.live = null;
                    self.live_count -= 1;
                } else l.row = to;
            }
        }
        for (self.linger.items) |l| self.slots.getPtr(l.key).?.linger_count += 1;

        // Slots with nothing visible left leave the map (collected first —
        // removing mid-iteration is not this map's contract).
        var empty = self.slots.iterator();
        while (empty.next()) |e| {
            if (e.value_ptr.live == null and e.value_ptr.linger_count == 0)
                dead.appendAssumeCapacity(e.key_ptr.*);
        }
        for (dead.items) |key| _ = self.slots.remove(key);
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

    /// Every visible Flow — live and Lingering — with its owning row index,
    /// each carrying the speed its ring reads at `event_now_ms` (the event
    /// clock, rates.zig — not the monotonic clock the lifecycle runs on).
    pub fn collect(
        self: *const Table,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(Entry),
        event_now_ms: u64,
    ) error{OutOfMemory}!void {
        try out.ensureUnusedCapacity(gpa, self.count());
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const l = e.value_ptr.live orelse continue;
            out.appendAssumeCapacity(entry(e.key_ptr.*, l, false, event_now_ms));
        }
        for (self.linger.items[self.linger_head..]) |l| {
            out.appendAssumeCapacity(entry(l.key, l.flow, true, event_now_ms));
        }
    }

    fn entry(key: FlowKey, flow: Live, lingering: bool, event_now_ms: u64) Entry {
        const speed = flow.rate.speed(event_now_ms);
        return .{ .row = flow.row, .flow = .{
            .proto = key.tuple.proto,
            .family = key.tuple.family,
            .local_addr = key.tuple.local_addr,
            .remote_addr = key.tuple.remote_addr,
            .local_port = key.tuple.local_port,
            .remote_port = key.tuple.remote_port,
            .generation = flow.generation,
            .sent = flow.sent,
            .recv = flow.recv,
            .sent_rate = speed.sent,
            .recv_rate = speed.recv,
            .lingering = lingering,
        } };
    }
};
