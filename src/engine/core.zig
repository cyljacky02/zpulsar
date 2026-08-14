//! The Engine thread's single-threaded state (ADR-0002: one owner, no
//! locks): per-PID In-session Totals fed from ring records, the Flow layer
//! (flows.zig) reconciled between events and IP Helper snapshots, and the
//! unified loss recovery — ring overflow and ETW EventsLost both re-baseline
//! from fresh tables and set the sticky health flag. Totals are honest or
//! marked, never silently low. All lifecycle timing runs on the caller's
//! monotonic `now_ms` so the whole layer is drivable by synthetic clocks.

const std = @import("std");
const event = @import("event.zig");
const flows = @import("flows.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

pub const Totals = struct {
    sent: u64 = 0,
    recv: u64 = 0,
};

pub const Core = struct {
    gpa: std.mem.Allocator,
    /// In-session Totals per payload PID. Never reset — loss marks, it does
    /// not erase (spec issue #18 "totals that are either exact or explicitly
    /// flagged"). Independent accumulators: they include bytes of Flows that
    /// have long left the list.
    totals: std.AutoHashMapUnmanaged(u32, Totals) = .empty,
    flows: flows.Table = .{},
    health: snapshot.Health = .{},
    seq: u64 = 0,
    /// Publish at least once even before any traffic.
    dirty: bool = true,
    /// Scratch pid→row-index map reused across snapshot builds.
    row_index: std.AutoHashMapUnmanaged(u32, usize) = .empty,
    /// Scratch flow-entry list reused across snapshot builds.
    flow_scratch: std.ArrayList(flows.Entry) = .empty,

    pub fn init(gpa: std.mem.Allocator) Core {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Core) void {
        self.totals.deinit(self.gpa);
        self.flows.deinit(self.gpa);
        self.row_index.deinit(self.gpa);
        self.flow_scratch.deinit(self.gpa);
    }

    /// Apply one ring record. OOM drops the record — the caller counts it as
    /// ring-equivalent loss.
    pub fn applyEvent(
        self: *Core,
        ev: event.NetEvent,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        switch (ev.op) {
            .send, .recv => {
                const gop = try self.totals.getOrPut(self.gpa, ev.pid);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                if (ev.op == .send)
                    gop.value_ptr.sent += ev.size
                else
                    gop.value_ptr.recv += ev.size;
                // First activity opens the Flow (raced the table snapshot,
                // or a new Generation after closure).
                const live = try self.flows.touch(self.gpa, flows.flowKey(ev), now_ms);
                if (ev.op == .send) live.sent += ev.size else live.recv += ev.size;
                self.dirty = true;
            },
            .connect => {
                try self.flows.connect(self.gpa, flows.flowKey(ev), now_ms);
                self.dirty = true;
            },
            .disconnect => {
                if (try self.flows.close(self.gpa, flows.flowKey(ev), now_ms))
                    self.dirty = true;
            },
        }
    }

    /// Time-driven Flow maintenance: Linger expiry (and, with them, UDP
    /// age-outs). Called at the Engine's flush-tick cadence.
    pub fn tick(self: *Core, now_ms: u64) error{OutOfMemory}!void {
        if (try self.flows.tick(self.gpa, now_ms)) self.dirty = true;
    }

    /// Cold-start seed and the 10 s reconciliation sweep share this: align
    /// the Flow list with a fresh IP Helper table snapshot.
    pub fn reconcile(
        self: *Core,
        rows: []const tables.SeededConn,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        if (try self.flows.reconcile(self.gpa, rows, now_ms)) self.dirty = true;
    }

    /// Process exit closes the PID's live Flows into normal Linger. The
    /// Process Rows ticket (#21) calls this from Kernel-Process exit events.
    pub fn processExited(
        self: *Core,
        pid: u32,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        if (try self.flows.processExited(self.gpa, pid, now_ms)) self.dirty = true;
    }

    /// Compare cumulative loss counters against the last observed values.
    /// True means new loss: the caller must re-baseline (fresh tables →
    /// `rebaseline`, or `flagRebaselined` if even the tables fail).
    pub fn noteLoss(self: *Core, ring_dropped: u64, etw_events_lost: u64) bool {
        const lost = ring_dropped > self.health.ring_dropped or
            etw_events_lost > self.health.etw_events_lost;
        self.health.ring_dropped = ring_dropped;
        self.health.etw_events_lost = etw_events_lost;
        if (lost) self.dirty = true;
        return lost;
    }

    /// Loss recovery: reconcile the Flow list against fresh tables. Totals
    /// stay — the sticky flag marks them as possibly low.
    pub fn rebaseline(
        self: *Core,
        rows: []const tables.SeededConn,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        try self.reconcile(rows, now_ms);
        self.flagRebaselined();
    }

    /// Loss happened but fresh tables are unavailable: the flag is still
    /// mandatory.
    pub fn flagRebaselined(self: *Core) void {
        self.health.rebaselined = true;
        self.dirty = true;
    }

    /// Build an immutable Snapshot of the current state in its own arena:
    /// one row per PID that has totals or owns a Flow (seeded pre-existing
    /// Flows appear), sorted by PID, each row's Flows grouped under it.
    pub fn buildSnapshot(self: *Core) error{OutOfMemory}!*snapshot.Snapshot {
        // Flows first, sorted (pid, identity, generation): each row's Flows
        // become one contiguous, deterministically ordered span.
        self.flow_scratch.clearRetainingCapacity();
        try self.flows.collect(self.gpa, &self.flow_scratch);
        std.mem.sort(flows.Entry, self.flow_scratch.items, {}, entryLessThan);

        self.row_index.clearRetainingCapacity();
        var count: usize = 0;
        var totals_it = self.totals.keyIterator();
        while (totals_it.next()) |pid| {
            try self.row_index.put(self.gpa, pid.*, count);
            count += 1;
        }
        for (self.flow_scratch.items) |e| {
            const gop = try self.row_index.getOrPut(self.gpa, e.pid);
            if (!gop.found_existing) {
                gop.value_ptr.* = count;
                count += 1;
            }
        }

        const snap = try snapshot.create(self.gpa, count, self.flow_scratch.items.len);
        errdefer snap.release();
        const rows = snapshot.mutableRows(snap);
        const flat = snapshot.mutableFlows(snap);

        var index_it = self.row_index.iterator();
        while (index_it.next()) |entry| {
            rows[entry.value_ptr.*] = .{ .pid = entry.key_ptr.* };
        }
        var t_it = self.totals.iterator();
        while (t_it.next()) |entry| {
            const row = &rows[self.row_index.get(entry.key_ptr.*).?];
            row.sent = entry.value_ptr.sent;
            row.recv = entry.value_ptr.recv;
        }
        std.mem.sort(snapshot.Row, rows, {}, rowPidLessThan);

        // Rows and collected flows are both pid-sorted: one merge walk
        // attaches each row's span and counts its live flows.
        for (self.flow_scratch.items, 0..) |e, i| flat[i] = e.flow;
        var fi: usize = 0;
        for (rows) |*row| {
            const start = fi;
            while (fi < self.flow_scratch.items.len and
                self.flow_scratch.items[fi].pid == row.pid) : (fi += 1)
            {
                const f = self.flow_scratch.items[fi].flow;
                if (!f.lingering) switch (f.proto) {
                    .tcp => row.tcp_conns += 1,
                    .udp => row.udp_socks += 1,
                };
            }
            row.flows = flat[start..fi];
        }

        self.seq += 1;
        snap.seq = self.seq;
        snap.health = self.health;
        self.dirty = false;
        return snap;
    }
};

fn rowPidLessThan(_: void, a: snapshot.Row, b: snapshot.Row) bool {
    return a.pid < b.pid;
}

/// Sort order for snapshot flows: owning pid, then flow identity, then
/// Generation — stable across builds so the UI never sees flows jump.
fn entryLessThan(_: void, a: flows.Entry, b: flows.Entry) bool {
    if (a.pid != b.pid) return a.pid < b.pid;
    const fa = a.flow;
    const fb = b.flow;
    if (fa.proto != fb.proto) return @intFromEnum(fa.proto) < @intFromEnum(fb.proto);
    if (fa.family != fb.family) return @intFromEnum(fa.family) < @intFromEnum(fb.family);
    if (fa.local_port != fb.local_port) return fa.local_port < fb.local_port;
    if (fa.remote_port != fb.remote_port) return fa.remote_port < fb.remote_port;
    switch (std.mem.order(u8, &fa.local_addr, &fb.local_addr)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    switch (std.mem.order(u8, &fa.remote_addr, &fb.remote_addr)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    return fa.generation < fb.generation;
}

// ---------------------------------------------------------------------------
// Tests — the seam the spec names: feed parsed records in, assert on
// published Snapshots (spec issue #18, Testing Decisions).
// ---------------------------------------------------------------------------

fn testEvent(op: event.Op, proto: event.Proto, pid: u32, size: u32, local_port: u16) event.NetEvent {
    return .{
        .op = op,
        .proto = proto,
        .family = .v4,
        .pid = pid,
        .size = size,
        .local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0)),
        .remote_addr = [4]u8{ 93, 184, 216, 34 } ++ @as([12]u8, @splat(0)),
        .local_port = local_port,
        .remote_port = 443,
        .timestamp_qpc = 0,
    };
}

fn rowForPid(rows: []const snapshot.Row, pid: u32) ?snapshot.Row {
    for (rows) |r| {
        if (r.pid == pid) return r;
    }
    return null;
}

test "send and recv accumulate independent u64 totals per payload PID" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .tcp, 100, 1500, 1), 0);
    try core.applyEvent(testEvent(.send, .tcp, 100, 500, 1), 0);
    try core.applyEvent(testEvent(.recv, .tcp, 100, 42, 1), 0);
    try core.applyEvent(testEvent(.recv, .udp, 200, 7, 2), 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 2), snap.rows.len);
    const p100 = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u64, 2000), p100.sent);
    try std.testing.expectEqual(@as(u64, 42), p100.recv);
    try std.testing.expectEqual(@as(u32, 1), p100.tcp_conns);
    const p200 = rowForPid(snap.rows, 200).?;
    try std.testing.expectEqual(@as(u64, 0), p200.sent);
    try std.testing.expectEqual(@as(u64, 7), p200.recv);
    try std.testing.expectEqual(@as(u32, 1), p200.udp_socks);
    // Rows come out sorted by PID.
    try std.testing.expect(snap.rows[0].pid < snap.rows[1].pid);
}

test "seeded pre-existing connections appear as rows with zero totals" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const seeded = [_]tables.SeededConn{.{
        .pid = 4242,
        .key = .{
            .proto = .tcp,
            .family = .v4,
            .local_addr = @splat(0),
            .remote_addr = @splat(1),
            .local_port = 5000,
            .remote_port = 443,
        },
    }};
    try core.reconcile(&seeded, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 4242).?;
    try std.testing.expectEqual(@as(u64, 0), row.sent + row.recv);
    try std.testing.expectEqual(@as(u32, 1), row.tcp_conns);
}

test "events racing the snapshot dedupe by normalized 5-tuple" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // The buffered event arrives first (drained after session start)...
    const ev = testEvent(.connect, .tcp, 100, 0, 51000);
    try core.applyEvent(ev, 0);
    // ...then the table snapshot lands carrying the same connection.
    try core.reconcile(&.{.{ .pid = 100, .key = event.connKey(ev) }}, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(u32, 1), rowForPid(snap.rows, 100).?.tcp_conns);

    // Same dedupe for UDP, where the table only knows the local endpoint.
    const udp_data = testEvent(.send, .udp, 300, 10, 5353);
    try core.applyEvent(udp_data, 0);
    try core.reconcile(&.{.{ .pid = 300, .key = event.connKey(udp_data) }}, 0);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(u32, 1), rowForPid(snap2.rows, 300).?.udp_socks);
}

test "disconnect closes the connection but totals persist" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const data = testEvent(.send, .tcp, 100, 999, 51000);
    try core.applyEvent(data, 0);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u32, 0), row.tcp_conns);
    try std.testing.expectEqual(@as(u64, 999), row.sent);
}

test "loss recovery: both loss sources set the sticky re-baselined flag" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .tcp, 100, 1000, 51000), 0);

    try std.testing.expect(!core.noteLoss(0, 0)); // quiet: no loss yet

    // Ring overflow.
    try std.testing.expect(core.noteLoss(3, 0));
    try core.rebaseline(&.{}, 0); // fresh tables happen to be empty
    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expect(snap.health.rebaselined);
    try std.testing.expectEqual(@as(u64, 3), snap.health.ring_dropped);
    // Totals are marked, never erased.
    try std.testing.expectEqual(@as(u64, 1000), rowForPid(snap.rows, 100).?.sent);

    // Same counters again: no new loss; ETW EventsLost alone triggers.
    try std.testing.expect(!core.noteLoss(3, 0));
    try std.testing.expect(core.noteLoss(3, 5));
    core.flagRebaselined(); // tables unavailable — flag is still mandatory
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expect(snap2.health.rebaselined); // sticky
    try std.testing.expectEqual(@as(u64, 5), snap2.health.etw_events_lost);
}

test "a TCP connect creates a live Flow under its Process Row" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    const f = row.flows[0];
    try std.testing.expectEqual(event.Proto.tcp, f.proto);
    try std.testing.expectEqual(@as(u16, 51000), f.local_port);
    try std.testing.expectEqual(@as(u16, 443), f.remote_port);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 93, 184, 216, 34 }, f.remote_addr[0..4]);
    try std.testing.expectEqual(@as(u32, 1), f.generation);
    try std.testing.expect(!f.lingering);
    try std.testing.expectEqual(@as(u32, 1), row.tcp_conns);
    // Hostname/service attribution are later tickets: fields exist, empty.
    try std.testing.expectEqual(@as(?[]const u8, null), f.remote_hostname);
    try std.testing.expectEqual(@as(?[]const u8, null), f.service);
}

test "a closed Flow Lingers 10 s with bytes retained in row totals" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const data = testEvent(.send, .tcp, 100, 999, 51000);
    try core.applyEvent(data, 1000);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 2000);

    // Lingering: still visible, dimmed, totals frozen, out of the live count.
    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u32, 0), row.tcp_conns);
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u64, 999), row.flows[0].sent);

    // One millisecond short of the Linger window: still there.
    try core.tick(11_999);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(usize, 1), rowForPid(snap2.rows, 100).?.flows.len);

    // At the boundary it leaves the flow list; the row keeps its bytes.
    try core.tick(12_000);
    const snap3 = try core.buildSnapshot();
    defer snap3.release();
    const row3 = rowForPid(snap3.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 0), row3.flows.len);
    try std.testing.expectEqual(@as(u64, 999), row3.sent);
}

test "endpoint reuse after closure starts a new Generation with fresh totals" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const data = testEvent(.send, .tcp, 100, 500, 51000);
    try core.applyEvent(data, 0);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 1000);

    // Reuse while the old Flow still Lingers: both visible, distinct.
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 2000);
    try core.applyEvent(testEvent(.send, .tcp, 100, 7, 51000), 2500);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 2), row.flows.len);
    // Identical identity sorts by Generation: the old Flow first.
    try std.testing.expectEqual(@as(u32, 1), row.flows[0].generation);
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u64, 500), row.flows[0].sent);
    try std.testing.expectEqual(@as(u32, 2), row.flows[1].generation);
    try std.testing.expect(!row.flows[1].lingering);
    // The old totals are never resumed: the new Generation starts from its
    // own bytes.
    try std.testing.expectEqual(@as(u64, 7), row.flows[1].sent);
    // The Process Row accumulates across Generations.
    try std.testing.expectEqual(@as(u64, 507), row.sent);
}

test "a connect on a live Flow that carried bytes closes it into a new Generation" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Bytes flow, then the disconnect is lost; the endpoints get reused.
    try core.applyEvent(testEvent(.send, .tcp, 100, 100, 51000), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 5000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 2), row.flows.len);
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u64, 100), row.flows[0].sent);
    try std.testing.expectEqual(@as(u32, 2), row.flows[1].generation);
    try std.testing.expectEqual(@as(u64, 0), row.flows[1].sent);
    try std.testing.expectEqual(@as(u32, 1), row.tcp_conns);
}

test "a connect on a zero-byte live Flow is the same connection seen twice" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Cold start: the table seeds the connection, then the buffered connect
    // event for the same connection drains — one Flow, not a churned pair.
    const ev = testEvent(.connect, .tcp, 100, 0, 51000);
    try core.reconcile(&.{.{ .pid = 100, .key = event.connKey(ev) }}, 0);
    try core.applyEvent(ev, 100);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expectEqual(@as(u32, 1), row.flows[0].generation);
    try std.testing.expect(!row.flows[0].lingering);
}

test "one UDP socket talking to two remotes is two Flows" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const a = testEvent(.send, .udp, 300, 10, 5353);
    var b = a;
    b.remote_addr = [4]u8{ 8, 8, 8, 8 } ++ @as([12]u8, @splat(0));
    b.remote_port = 53;
    try core.applyEvent(a, 0);
    try core.applyEvent(b, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 300).?;
    // The Flow key keeps UDP's real remote endpoint (spec issue #18 Data
    // model) — unlike the local-only table-dedupe key.
    try std.testing.expectEqual(@as(usize, 2), row.flows.len);
    try std.testing.expectEqual(@as(u32, 2), row.udp_socks);
    try std.testing.expect(row.flows[0].remote_port != row.flows[1].remote_port);
}

test "UDP Flows age out after 60 s inactivity into normal Linger" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .udp, 300, 10, 5353), 0);
    // Activity resets the clock.
    try core.applyEvent(testEvent(.recv, .udp, 300, 4, 5353), 30_000);

    try core.tick(89_999);
    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expect(!rowForPid(snap.rows, 300).?.flows[0].lingering);

    // 60 s after the last activity: closed into normal Linger…
    try core.tick(90_000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 300).?;
    try std.testing.expect(row2.flows[0].lingering);
    try std.testing.expectEqual(@as(u32, 0), row2.udp_socks);

    // …and 10 s later it leaves, bytes retained in the row.
    try core.tick(100_000);
    const snap3 = try core.buildSnapshot();
    defer snap3.release();
    const row3 = rowForPid(snap3.rows, 300).?;
    try std.testing.expectEqual(@as(usize, 0), row3.flows.len);
    try std.testing.expectEqual(@as(u64, 10), row3.sent);
    try std.testing.expectEqual(@as(u64, 4), row3.recv);
}

test "a real conversation replaces a seeded UDP socket's zero-remote placeholder" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Cold start: the UDP owner table only knows the local endpoint, so the
    // idle socket appears as a zero-remote placeholder Flow.
    const ev = testEvent(.send, .udp, 300, 10, 5353);
    try core.reconcile(&.{.{ .pid = 300, .key = event.connKey(ev) }}, 0);
    const snap = try core.buildSnapshot();
    defer snap.release();
    const seeded_row = rowForPid(snap.rows, 300).?;
    try std.testing.expectEqual(@as(usize, 1), seeded_row.flows.len);
    try std.testing.expectEqual(@as(u16, 0), seeded_row.flows[0].remote_port);

    // Traffic on the socket: the real conversation supersedes the byte-less
    // placeholder outright — one Flow, not a socket shown twice.
    try core.applyEvent(ev, 1000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    const row = rowForPid(snap2.rows, 300).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expectEqual(@as(u16, 443), row.flows[0].remote_port);
    try std.testing.expectEqual(@as(u64, 10), row.flows[0].sent);
}

test "the reconciliation sweep closes TCP Flows whose close events were lost" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const keep = testEvent(.send, .tcp, 100, 10, 51000);
    const lost = testEvent(.send, .tcp, 100, 20, 51001);
    try core.applyEvent(keep, 0);
    try core.applyEvent(lost, 0);

    // The sweep's fresh table still shows one connection; the other is gone
    // — its disconnect event never arrived.
    try core.reconcile(&.{.{ .pid = 100, .key = event.connKey(keep) }}, 5000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 2), row.flows.len);
    try std.testing.expectEqual(@as(u16, 51000), row.flows[0].local_port);
    try std.testing.expect(!row.flows[0].lingering);
    try std.testing.expectEqual(@as(u16, 51001), row.flows[1].local_port);
    try std.testing.expect(row.flows[1].lingering);
    try std.testing.expectEqual(@as(u32, 1), row.tcp_conns);
}

test "the sweep keeps a seeded idle UDP socket alive exactly as long as it stays bound" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const ev = testEvent(.send, .udp, 300, 10, 5353);
    const table_row: tables.SeededConn = .{ .pid = 300, .key = event.connKey(ev) };
    try core.reconcile(&.{table_row}, 0);

    // Still in the table at 55 s: refreshed past the 60 s age-out.
    try core.reconcile(&.{table_row}, 55_000);
    try core.tick(60_000);
    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expect(!rowForPid(snap.rows, 300).?.flows[0].lingering);

    // Socket unbound: the next sweep closes the placeholder into Linger.
    try core.reconcile(&.{}, 70_000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expect(rowForPid(snap2.rows, 300).?.flows[0].lingering);
}

test "process exit closes its live Flows into normal Linger" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .tcp, 100, 50, 51000), 0);
    try core.applyEvent(testEvent(.send, .udp, 100, 5, 5353), 0);
    try core.applyEvent(testEvent(.send, .tcp, 200, 9, 52000), 0);

    try core.processExited(100, 1000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const exited = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 2), exited.flows.len);
    try std.testing.expect(exited.flows[0].lingering);
    try std.testing.expect(exited.flows[1].lingering);
    try std.testing.expectEqual(@as(u64, 55), exited.sent);
    try std.testing.expect(!rowForPid(snap.rows, 200).?.flows[0].lingering);

    // Normal Linger: gone at 10 s, the row and its totals stay.
    try core.tick(11_000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 0), row2.flows.len);
    try std.testing.expectEqual(@as(u64, 55), row2.sent);
}

test "a half-closed table row is presence, never a seed" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // An event-closed Flow whose table row lingers in FIN_WAIT/CLOSE_WAIT
    // (those states can persist for minutes) must not come back as a ghost
    // zero-byte Generation.
    const data = testEvent(.send, .tcp, 100, 30, 51000);
    try core.applyEvent(data, 0);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 1000);
    try core.reconcile(&.{.{ .pid = 100, .key = event.connKey(data), .closing = true }}, 5000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u32, 0), row.tcp_conns);

    // But a live Flow whose row went half-closed stays open — data can
    // still move; the event-driven close will land.
    const live = testEvent(.send, .tcp, 200, 40, 52000);
    try core.applyEvent(live, 0);
    try core.reconcile(&.{.{ .pid = 200, .key = event.connKey(live), .closing = true }}, 5000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(u32, 1), rowForPid(snap2.rows, 200).?.tcp_conns);
}

test "a held Snapshot never changes while the Engine keeps updating" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    var published: snapshot.Published = try .init();
    defer published.deinit();

    try core.applyEvent(testEvent(.send, .tcp, 100, 1000, 51000), 0);
    published.publish(try core.buildSnapshot());
    const held = published.acquire().?;
    defer held.release();

    // The Engine moves on: more bytes, a new PID, loss, a new Snapshot.
    try core.applyEvent(testEvent(.send, .tcp, 100, 5000, 51000), 0);
    try core.applyEvent(testEvent(.recv, .tcp, 777, 1, 4000), 0);
    _ = core.noteLoss(9, 0);
    core.flagRebaselined();
    published.publish(try core.buildSnapshot());

    // The held reader still sees the old world, bit for bit — its Flows too.
    try std.testing.expectEqual(@as(usize, 1), held.rows.len);
    try std.testing.expectEqual(@as(u64, 1000), held.rows[0].sent);
    try std.testing.expectEqual(@as(usize, 1), held.rows[0].flows.len);
    try std.testing.expectEqual(@as(u64, 1000), held.rows[0].flows[0].sent);
    try std.testing.expect(!held.health.rebaselined);

    // A fresh reader sees the new one.
    const fresh = published.acquire().?;
    defer fresh.release();
    try std.testing.expect(fresh.seq > held.seq);
    try std.testing.expectEqual(@as(u64, 6000), rowForPid(fresh.rows, 100).?.sent);
    try std.testing.expect(fresh.health.rebaselined);
}
