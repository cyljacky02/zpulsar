//! The Engine thread's single-threaded state (ADR-0002: one owner, no
//! locks): per-PID In-session Totals fed from ring records, the connection
//! list reconciled between events and IP Helper snapshots, and the unified
//! loss recovery — ring overflow and ETW EventsLost both re-baseline from
//! fresh tables and set the sticky health flag. Totals are honest or marked,
//! never silently low.

const std = @import("std");
const event = @import("event.zig");
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
    /// flagged").
    totals: std.AutoHashMapUnmanaged(u32, Totals) = .empty,
    /// Live connections by normalized key — the cold-start dedupe seam:
    /// seeded rows and event-inserted entries meet here.
    conns: std.AutoHashMapUnmanaged(event.ConnKey, u32) = .empty,
    health: snapshot.Health = .{},
    seq: u64 = 0,
    /// Publish at least once even before any traffic.
    dirty: bool = true,
    /// Scratch pid→row-index map reused across snapshot builds.
    row_index: std.AutoHashMapUnmanaged(u32, usize) = .empty,

    pub fn init(gpa: std.mem.Allocator) Core {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Core) void {
        self.totals.deinit(self.gpa);
        self.conns.deinit(self.gpa);
        self.row_index.deinit(self.gpa);
    }

    /// Apply one ring record. OOM drops the record — the caller counts it as
    /// ring-equivalent loss.
    pub fn applyEvent(self: *Core, ev: event.NetEvent) error{OutOfMemory}!void {
        switch (ev.op) {
            .send, .recv => {
                const gop = try self.totals.getOrPut(self.gpa, ev.pid);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                if (ev.op == .send)
                    gop.value_ptr.sent += ev.size
                else
                    gop.value_ptr.recv += ev.size;
                // A connection first seen through data (raced the snapshot,
                // or newer than it) is inserted from the event.
                try self.upsertConn(event.connKey(ev), ev.pid);
                self.dirty = true;
            },
            .connect => {
                try self.upsertConn(event.connKey(ev), ev.pid);
                self.dirty = true;
            },
            .disconnect => {
                if (self.conns.remove(event.connKey(ev))) self.dirty = true;
            },
        }
    }

    fn upsertConn(self: *Core, key: event.ConnKey, pid: u32) error{OutOfMemory}!void {
        const gop = try self.conns.getOrPut(self.gpa, key);
        // Events carry the authoritative payload PID: existing entries keep
        // theirs (a seeded row and its event describe the same owner).
        if (!gop.found_existing) gop.value_ptr.* = pid;
    }

    /// Cold-start seed: insert table rows that no event has claimed yet.
    /// Events that raced the snapshot already sit in the map under the same
    /// normalized key — that is the dedupe.
    pub fn seed(self: *Core, rows: []const tables.SeededConn) error{OutOfMemory}!void {
        for (rows) |r| {
            const before = self.conns.count();
            try self.upsertConn(r.key, r.pid);
            if (self.conns.count() != before) self.dirty = true;
        }
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

    /// Loss recovery: rebuild the connection list from fresh tables. Totals
    /// stay — the sticky flag marks them as possibly low.
    pub fn rebaseline(self: *Core, rows: []const tables.SeededConn) error{OutOfMemory}!void {
        self.conns.clearRetainingCapacity();
        for (rows) |r| try self.upsertConn(r.key, r.pid);
        self.flagRebaselined();
    }

    /// Loss happened but fresh tables are unavailable: the flag is still
    /// mandatory.
    pub fn flagRebaselined(self: *Core) void {
        self.health.rebaselined = true;
        self.dirty = true;
    }

    /// Build an immutable Snapshot of the current state in its own arena:
    /// one row per PID that has totals or owns a connection (pre-existing
    /// idle connections appear), sorted by PID.
    pub fn buildSnapshot(self: *Core) error{OutOfMemory}!*snapshot.Snapshot {
        self.row_index.clearRetainingCapacity();

        var count: usize = 0;
        var totals_it = self.totals.keyIterator();
        while (totals_it.next()) |pid| {
            try self.row_index.put(self.gpa, pid.*, count);
            count += 1;
        }
        var conns_it = self.conns.valueIterator();
        while (conns_it.next()) |pid| {
            const gop = try self.row_index.getOrPut(self.gpa, pid.*);
            if (!gop.found_existing) {
                gop.value_ptr.* = count;
                count += 1;
            }
        }

        const snap = try snapshot.create(self.gpa, count);
        errdefer snap.release();
        const rows = snapshot.mutableRows(snap);

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
        var c_it = self.conns.iterator();
        while (c_it.next()) |entry| {
            const row = &rows[self.row_index.get(entry.value_ptr.*).?];
            switch (entry.key_ptr.proto) {
                .tcp => row.tcp_conns += 1,
                .udp => row.udp_socks += 1,
            }
        }
        std.mem.sort(snapshot.Row, rows, {}, rowPidLessThan);

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
    try core.applyEvent(testEvent(.send, .tcp, 100, 1500, 1));
    try core.applyEvent(testEvent(.send, .tcp, 100, 500, 1));
    try core.applyEvent(testEvent(.recv, .tcp, 100, 42, 1));
    try core.applyEvent(testEvent(.recv, .udp, 200, 7, 2));

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
    try core.seed(&seeded);

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
    try core.applyEvent(ev);
    // ...then the table snapshot lands carrying the same connection.
    try core.seed(&.{.{ .pid = 100, .key = event.connKey(ev) }});

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(u32, 1), rowForPid(snap.rows, 100).?.tcp_conns);

    // Same dedupe for UDP, where the table only knows the local endpoint.
    const udp_data = testEvent(.send, .udp, 300, 10, 5353);
    try core.applyEvent(udp_data);
    try core.seed(&.{.{ .pid = 300, .key = event.connKey(udp_data) }});
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(u32, 1), rowForPid(snap2.rows, 300).?.udp_socks);
}

test "disconnect closes the connection but totals persist" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const data = testEvent(.send, .tcp, 100, 999, 51000);
    try core.applyEvent(data);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u32, 0), row.tcp_conns);
    try std.testing.expectEqual(@as(u64, 999), row.sent);
}

test "loss recovery: both loss sources set the sticky re-baselined flag" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .tcp, 100, 1000, 51000));

    try std.testing.expect(!core.noteLoss(0, 0)); // quiet: no loss yet

    // Ring overflow.
    try std.testing.expect(core.noteLoss(3, 0));
    try core.rebaseline(&.{}); // fresh tables happen to be empty
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

test "a held Snapshot never changes while the Engine keeps updating" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    var published: snapshot.Published = try .init();
    defer published.deinit();

    try core.applyEvent(testEvent(.send, .tcp, 100, 1000, 51000));
    published.publish(try core.buildSnapshot());
    const held = published.acquire().?;
    defer held.release();

    // The Engine moves on: more bytes, a new PID, loss, a new Snapshot.
    try core.applyEvent(testEvent(.send, .tcp, 100, 5000, 51000));
    try core.applyEvent(testEvent(.recv, .tcp, 777, 1, 4000));
    _ = core.noteLoss(9, 0);
    core.flagRebaselined();
    published.publish(try core.buildSnapshot());

    // The held reader still sees the old world, bit for bit.
    try std.testing.expectEqual(@as(usize, 1), held.rows.len);
    try std.testing.expectEqual(@as(u64, 1000), held.rows[0].sent);
    try std.testing.expect(!held.health.rebaselined);

    // A fresh reader sees the new one.
    const fresh = published.acquire().?;
    defer fresh.release();
    try std.testing.expect(fresh.seq > held.seq);
    try std.testing.expectEqual(@as(u64, 6000), rowForPid(fresh.rows, 100).?.sent);
    try std.testing.expect(fresh.health.rebaselined);
}
