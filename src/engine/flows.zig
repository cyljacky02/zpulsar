//! The Flow layer (issue #22; CONTEXT.md "Flow", "Generation", "Linger"):
//! per-Flow identity, lifecycle, and totals inside the Engine thread's
//! single-threaded state. Flows are keyed (protocol, local endpoint, remote
//! endpoint, owning PID); endpoint reuse after closure starts a new
//! Generation — never resuming the old Flow or its totals. Closed Flows
//! Linger 10 s and then leave the list; their bytes live on in the Process
//! Row totals, which are independent accumulators (core.zig), never a sum
//! of visible flows.

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

const Live = struct {
    generation: u32,
    sent: u64 = 0,
    recv: u64 = 0,
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

/// A closed Flow riding out its Linger window. Totals are frozen at close.
const Lingering = struct {
    key: FlowKey,
    generation: u32,
    sent: u64,
    recv: u64,
    expires_at_ms: u64,
};

/// UDP socket presence: how many live UDP Flows share one (family, local
/// endpoint, PID). Keeps table-seeded zero-remote placeholders and real
/// per-remote conversations from double-representing one socket.
const UdpLocalKey = struct {
    family: event.Family,
    local_addr: [16]u8,
    local_port: u16,
    pid: u32,
};

fn udpLocalKey(key: FlowKey) UdpLocalKey {
    return .{
        .family = key.tuple.family,
        .local_addr = key.tuple.local_addr,
        .local_port = key.tuple.local_port,
        .pid = key.pid,
    };
}

fn isZeroRemote(tuple: event.ConnKey) bool {
    return tuple.remote_port == 0 and
        std.mem.allEqual(u8, &tuple.remote_addr, 0);
}

/// One Flow ready for Snapshot building, still carrying its owning PID.
pub const Entry = struct {
    pid: u32,
    flow: snapshot.Flow,
};

pub const Table = struct {
    slots: std.AutoHashMapUnmanaged(FlowKey, Slot) = .empty,
    /// Closed Flows in close order — monotonic time makes this expiry order.
    linger: std.ArrayList(Lingering) = .empty,
    linger_head: usize = 0,
    live_count: usize = 0,
    udp_local: std.AutoHashMapUnmanaged(UdpLocalKey, u32) = .empty,
    /// Sweep scratch: the current table snapshot's tuples, reused per sweep.
    scratch_tuples: std.AutoHashMapUnmanaged(event.ConnKey, void) = .empty,

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        self.slots.deinit(gpa);
        self.linger.deinit(gpa);
        self.udp_local.deinit(gpa);
        self.scratch_tuples.deinit(gpa);
    }

    pub fn count(self: *const Table) usize {
        return self.live_count + (self.linger.items.len - self.linger_head);
    }

    /// Data or connect activity on a key: refresh the live Flow, or open a
    /// new Generation if the key has none (first activity after closure).
    pub fn touch(
        self: *Table,
        gpa: std.mem.Allocator,
        key: FlowKey,
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
        if (key.tuple.proto == .udp) {
            const gop = try self.udp_local.getOrPut(gpa, udpLocalKey(key));
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
        }
        errdefer if (key.tuple.proto == .udp) self.releaseUdpLocal(key);
        const gop = try self.slots.getOrPut(gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.last_gen += 1;
        gop.value_ptr.live = .{
            .generation = gop.value_ptr.last_gen,
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
        now_ms: u64,
    ) error{OutOfMemory}!void {
        if (self.slots.getPtr(key)) |slot| {
            if (slot.live) |l| {
                if (l.sent + l.recv > 0) _ = try self.close(gpa, key, now_ms);
            }
        }
        _ = try self.touch(gpa, key, now_ms);
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
        self.releaseUdpLocal(placeholder);
        if (slot.linger_count == 0) _ = self.slots.remove(placeholder);
    }

    fn releaseUdpLocal(self: *Table, key: FlowKey) void {
        const local = udpLocalKey(key);
        const n = self.udp_local.getPtr(local).?;
        n.* -= 1;
        if (n.* == 0) _ = self.udp_local.remove(local);
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
            .sent = l.sent,
            .recv = l.recv,
            .expires_at_ms = now_ms + linger_ms,
        });
        slot.live = null;
        slot.linger_count += 1;
        self.live_count -= 1;
        if (key.tuple.proto == .udp) self.releaseUdpLocal(key);
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
    pub fn reconcile(
        self: *Table,
        gpa: std.mem.Allocator,
        rows: []const tables.SeededConn,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        var changed = false;
        self.scratch_tuples.clearRetainingCapacity();
        for (rows) |r| try self.scratch_tuples.put(gpa, r.key, {});
        // The tuple check is PID-blind on purpose: duplicated/inherited
        // sockets appear as sibling Flows, but the table names one owner.
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.live == null) continue;
            const tuple = e.key_ptr.tuple;
            switch (tuple.proto) {
                .tcp => if (!self.scratch_tuples.contains(tuple)) {
                    _ = try self.close(gpa, e.key_ptr.*, now_ms);
                    changed = true;
                },
                .udp => if (isZeroRemote(tuple)) {
                    if (self.scratch_tuples.contains(tuple)) {
                        e.value_ptr.live.?.last_activity_ms = now_ms;
                    } else {
                        _ = try self.close(gpa, e.key_ptr.*, now_ms);
                        changed = true;
                    }
                },
            }
        }
        // Seed table rows whose key has no live Flow. Half-closed rows are
        // presence only — seeding them would revive event-closed Flows as
        // ghosts. A live UDP Flow on the same socket already represents it —
        // the local-only table row would double it (the seed's job is
        // presence, and presence is covered).
        for (rows) |r| {
            if (r.closing) continue;
            const key: FlowKey = .{ .tuple = r.key, .pid = r.pid };
            if (self.slots.getPtr(key)) |slot| {
                if (slot.live != null) continue;
            }
            if (r.key.proto == .udp and self.udp_local.contains(udpLocalKey(key)))
                continue;
            _ = try self.touch(gpa, key, now_ms);
            changed = true;
        }
        return changed;
    }

    /// Process exit closes its live Flows immediately into normal Linger
    /// (spec issue #18 Data model). Wired to Kernel-Process exit events by
    /// the Process Rows ticket (#21).
    pub fn processExited(
        self: *Table,
        gpa: std.mem.Allocator,
        pid: u32,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        var changed = false;
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.key_ptr.pid != pid) continue;
            if (e.value_ptr.live == null) continue;
            _ = try self.close(gpa, e.key_ptr.*, now_ms);
            changed = true;
        }
        return changed;
    }

    /// Every visible Flow — live and Lingering — with its owning PID.
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
                entry(e.key_ptr.*, l.generation, l.sent, l.recv, false),
            );
        }
        for (self.linger.items[self.linger_head..]) |l| {
            out.appendAssumeCapacity(entry(l.key, l.generation, l.sent, l.recv, true));
        }
    }

    fn entry(key: FlowKey, generation: u32, sent: u64, recv: u64, lingering: bool) Entry {
        return .{ .pid = key.pid, .flow = .{
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
        } };
    }
};
