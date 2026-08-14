//! The Engine thread's single-threaded state (ADR-0002: one owner, no
//! locks). Rows are process instances keyed (PID, payload CreateTime) —
//! PID reuse yields a fresh row, exited rows persist all session with their
//! In-session Totals intact, and traffic arriving inside the flush window
//! after an exit still lands on the exited row (issue #21). The connection
//! list is reconciled between events and IP Helper snapshots, and the
//! unified loss recovery — ring overflow and ETW EventsLost both re-baseline
//! from fresh tables and set the sticky health flag. Totals are honest or
//! marked, never silently low.

const std = @import("std");
const device_map = @import("device_map.zig");
const event = @import("event.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

/// One process instance. `create_time == 0` marks a placeholder: traffic or
/// a table row arrived before the identity did (cold-start race); the first
/// start/rundown event adopts it in place, totals kept.
const ProcessRow = struct {
    pid: u32,
    /// Raw payload CreateTime FILETIME — with pid, the row key.
    create_time: u64,
    exited: bool = false,
    /// Raw payload ExitTime FILETIME; 0 when unknown (instance retired only
    /// because its PID reappeared).
    exit_time: u64 = 0,
    /// Display path (drive-letter converted), owned by Core's gpa. Named by
    /// start/rundown payloads only — never by the stop event (its name is
    /// kernel-truncated, research §2.4).
    name: []const u8 = "",
    sent: u64 = 0,
    recv: u64 = 0,
};

pub const Core = struct {
    gpa: std.mem.Allocator,
    /// All Process Rows, append-only: exited rows persist all session
    /// (eviction caps are a later ticket), so indices are stable.
    rows: std.ArrayList(ProcessRow) = .empty,
    /// The row currently owning each PID (live, or a placeholder).
    live_by_pid: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    /// The most recently exited row per PID — where post-exit flush-window
    /// traffic goes.
    exited_by_pid: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    /// Live connections by normalized key → owning row index. The cold-start
    /// dedupe seam: seeded rows and event-inserted entries meet here.
    conns: std.AutoHashMapUnmanaged(event.ConnKey, u32) = .empty,
    /// NT-device → drive-letter display conversion. Populated by the runner
    /// at start; owned (and freed) by Core.
    drive_map: device_map.DriveMap = .{},
    health: snapshot.Health = .{},
    seq: u64 = 0,
    /// Publish at least once even before any traffic.
    dirty: bool = true,

    pub fn init(gpa: std.mem.Allocator) Core {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Core) void {
        for (self.rows.items) |row| self.gpa.free(row.name);
        self.rows.deinit(self.gpa);
        self.live_by_pid.deinit(self.gpa);
        self.exited_by_pid.deinit(self.gpa);
        self.conns.deinit(self.gpa);
        self.drive_map.deinit(self.gpa);
    }

    /// Apply one net-event ring record. OOM drops the record — the caller
    /// counts it as ring-equivalent loss.
    pub fn applyEvent(self: *Core, ev: event.NetEvent) error{OutOfMemory}!void {
        switch (ev.op) {
            .send, .recv => {
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                const row = &self.rows.items[idx];
                if (ev.op == .send)
                    row.sent += ev.size
                else
                    row.recv += ev.size;
                // A connection first seen through data (raced the snapshot,
                // or newer than it) is inserted from the event.
                try self.upsertConn(event.connKey(ev), idx);
                self.dirty = true;
            },
            .connect => {
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                try self.upsertConn(event.connKey(ev), idx);
                self.dirty = true;
            },
            .disconnect => {
                if (self.conns.remove(event.connKey(ev))) self.dirty = true;
            },
        }
    }

    /// Apply one Kernel-Process ring record: row identity and lifetime.
    pub fn applyProcess(self: *Core, ev: event.ProcessEvent) error{OutOfMemory}!void {
        switch (ev.kind) {
            .start, .rundown => {
                if (self.live_by_pid.get(ev.pid)) |idx| {
                    const known = self.rows.items[idx].create_time;
                    if (known == ev.create_time) {
                        // Start-vs-rundown duplicate: same row key.
                        try self.nameRow(idx, ev);
                    } else if (known == 0) {
                        // Placeholder from traffic that raced this event —
                        // adopt the identity in place, totals kept.
                        self.rows.items[idx].create_time = ev.create_time;
                        try self.nameRow(idx, ev);
                    } else {
                        // A different instance owns the PID and we never saw
                        // its stop: retire it, fresh row for the new one.
                        try self.retire(idx, 0);
                        try self.nameRow(try self.newRow(ev.pid, ev.create_time), ev);
                    }
                } else {
                    try self.nameRow(try self.newRow(ev.pid, ev.create_time), ev);
                }
                self.dirty = true;
            },
            .stop => {
                if (self.live_by_pid.get(ev.pid)) |idx| {
                    const known = self.rows.items[idx].create_time;
                    if (known == ev.create_time or known == 0) {
                        // A placeholder adopts the key from the stop payload
                        // — but never its name (research §2.4).
                        self.rows.items[idx].create_time = ev.create_time;
                        try self.retire(idx, ev.exit_time);
                        self.dirty = true;
                    }
                    // A stop for some other instance of this PID: the row it
                    // describes was already retired (or never known) — the
                    // exit-time backfill below still applies.
                } else {
                    // No row at all (exited before the rundown burst landed):
                    // an exited row keyed from the stop payload keeps any
                    // late traffic attributed. Name stays empty.
                    try self.retire(try self.newRow(ev.pid, ev.create_time), ev.exit_time);
                    self.dirty = true;
                }
                if (self.exited_by_pid.get(ev.pid)) |prev| {
                    const row = &self.rows.items[prev];
                    if (row.create_time == ev.create_time and row.exit_time == 0) {
                        row.exit_time = ev.exit_time;
                        self.dirty = true;
                    }
                }
            },
        }
    }

    /// The row traffic stamped `ts` should attribute to. Post-exit events
    /// inside the flush window land on the exited instance, never on a fresh
    /// or wrong row: header timestamps and payload CreateTime share the
    /// FILETIME domain (research §3), so an event stamped before the live
    /// row's process existed belongs to the PID's previous holder.
    fn rowForTraffic(self: *Core, pid: u32, ts: i64) error{OutOfMemory}!u32 {
        if (self.live_by_pid.get(pid)) |idx| {
            const created = self.rows.items[idx].create_time;
            if (created != 0 and ts > 0 and @as(u64, @intCast(ts)) < created) {
                if (self.exited_by_pid.get(pid)) |prev| return prev;
            }
            return idx;
        }
        if (self.exited_by_pid.get(pid)) |prev| return prev;
        // Traffic before any identity (cold-start race, loss): a placeholder
        // row that the first start/rundown event adopts.
        return self.newRow(pid, 0);
    }

    /// Append a row and make it the PID's current owner.
    fn newRow(self: *Core, pid: u32, create_time: u64) error{OutOfMemory}!u32 {
        const idx: u32 = @intCast(self.rows.items.len);
        try self.rows.append(self.gpa, .{ .pid = pid, .create_time = create_time });
        try self.live_by_pid.put(self.gpa, pid, idx);
        return idx;
    }

    /// Mark a row exited and stop routing its PID to it (except through
    /// exited_by_pid, for the flush window).
    fn retire(self: *Core, idx: u32, exit_time: u64) error{OutOfMemory}!void {
        const row = &self.rows.items[idx];
        row.exited = true;
        row.exit_time = exit_time;
        _ = self.live_by_pid.remove(row.pid);
        try self.exited_by_pid.put(self.gpa, row.pid, idx);
    }

    /// Set a row's display name from a start/rundown payload, first writer
    /// wins (start and rundown carry the same name).
    fn nameRow(self: *Core, idx: u32, ev: event.ProcessEvent) error{OutOfMemory}!void {
        if (ev.name_len == 0 or self.rows.items[idx].name.len != 0) return;
        var buf: [3 * event.max_image_name_units]u8 = undefined;
        const n = std.unicode.wtf16LeToWtf8(&buf, ev.name());
        self.rows.items[idx].name = try self.drive_map.displayPath(self.gpa, buf[0..n]);
    }

    fn upsertConn(self: *Core, key: event.ConnKey, row_idx: u32) error{OutOfMemory}!void {
        const gop = try self.conns.getOrPut(self.gpa, key);
        // Existing entries keep their row — a seeded entry and its event
        // describe the same owner.
        if (!gop.found_existing) gop.value_ptr.* = row_idx;
    }

    /// Cold-start seed: insert table rows that no event has claimed yet.
    /// Events that raced the snapshot already sit in the map under the same
    /// normalized key — that is the dedupe.
    pub fn seed(self: *Core, rows: []const tables.SeededConn) error{OutOfMemory}!void {
        for (rows) |r| {
            const idx = try self.rowForTraffic(r.pid, 0);
            const before = self.conns.count();
            try self.upsertConn(r.key, idx);
            if (self.conns.count() != before) self.dirty = true;
        }
    }

    /// Compare cumulative loss counters against the last observed values.
    /// True means new loss: the caller must re-baseline (fresh tables →
    /// `rebaseline`, or `flagRebaselined` if even the tables fail) and
    /// re-issue the process rundown.
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
        for (rows) |r| try self.upsertConn(r.key, try self.rowForTraffic(r.pid, 0));
        self.flagRebaselined();
    }

    /// Loss happened but fresh tables are unavailable: the flag is still
    /// mandatory.
    pub fn flagRebaselined(self: *Core) void {
        self.health.rebaselined = true;
        self.dirty = true;
    }

    /// Build an immutable Snapshot of the current state in its own arena:
    /// one row per process instance (live, exited, and placeholders), sorted
    /// by PID with exited instances before their PID's live successor.
    pub fn buildSnapshot(self: *Core) error{OutOfMemory}!*snapshot.Snapshot {
        const snap = try snapshot.create(self.gpa, self.rows.items.len);
        errdefer snap.release();
        const out = snapshot.mutableRows(snap);

        for (self.rows.items, out) |row, *dst| {
            dst.* = .{
                .pid = row.pid,
                .name = try snapshot.arenaDupe(snap, row.name),
                .exited = row.exited,
                .sent = row.sent,
                .recv = row.recv,
            };
        }
        // Connection counts address rows by position — count before sorting.
        var c_it = self.conns.iterator();
        while (c_it.next()) |entry| {
            const dst = &out[entry.value_ptr.*];
            switch (entry.key_ptr.proto) {
                .tcp => dst.tcp_conns += 1,
                .udp => dst.udp_socks += 1,
            }
        }
        std.mem.sort(snapshot.Row, out, {}, rowOrder);

        self.seq += 1;
        snap.seq = self.seq;
        snap.health = self.health;
        self.dirty = false;
        return snap;
    }
};

/// PID ascending; instances sharing a reused PID show the exited one first.
fn rowOrder(_: void, a: snapshot.Row, b: snapshot.Row) bool {
    if (a.pid != b.pid) return a.pid < b.pid;
    return a.exited and !b.exited;
}

// ---------------------------------------------------------------------------
// Tests — the seam the spec names: feed parsed records in, assert on
// published Snapshots (spec issue #18, Testing Decisions).
// ---------------------------------------------------------------------------

fn testEvent(op: event.Op, proto: event.Proto, pid: u32, size: u32, local_port: u16) event.NetEvent {
    return testEventAt(op, proto, pid, size, local_port, 0);
}

fn testEventAt(
    op: event.Op,
    proto: event.Proto,
    pid: u32,
    size: u32,
    local_port: u16,
    ts: i64,
) event.NetEvent {
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
        .timestamp_ft = ts,
    };
}

fn procEvent(
    kind: event.ProcessKind,
    pid: u32,
    create_time: u64,
    exit_time: u64,
    comptime name: []const u8,
) event.ProcessEvent {
    var ev: event.ProcessEvent = .{
        .kind = kind,
        .pid = pid,
        .create_time = create_time,
        .exit_time = exit_time,
        .name_len = 0,
        .name_buf = undefined,
    };
    ev.setName(std.unicode.utf8ToUtf16LeStringLiteral(name));
    return ev;
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

test "start and rundown for the same instance dedupe on the row key" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\ping.exe"));
    try core.applyProcess(procEvent(.rundown, 100, 111, 0, "\\x\\ping.exe"));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expectEqualStrings("\\x\\ping.exe", snap.rows[0].name);
    try std.testing.expect(!snap.rows[0].exited);
}

test "traffic racing the rundown lands on a placeholder the identity adopts" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Cold start: bytes arrive before the CAPTURE_STATE burst.
    try core.applyEvent(testEvent(.send, .tcp, 100, 5000, 1));
    try core.applyProcess(procEvent(.rundown, 100, 111, 0, "\\x\\svchost.exe"));

    const snap = try core.buildSnapshot();
    defer snap.release();
    // One row — not a nameless placeholder plus a named duplicate.
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expectEqualStrings("\\x\\svchost.exe", snap.rows[0].name);
    try std.testing.expectEqual(@as(u64, 5000), snap.rows[0].sent);
}

test "exit marks the row with totals intact; a reused PID gets a fresh row" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"));
    try core.applyEvent(testEventAt(.send, .tcp, 100, 700, 1, 150));
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 700), snap.rows[0].sent);
    try std.testing.expectEqualStrings("\\x\\a.exe", snap.rows[0].name);

    // The PID comes back as a different process: fresh row, fresh totals.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"));
    try core.applyEvent(testEventAt(.send, .tcp, 100, 11, 1, 600));
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(usize, 2), snap2.rows.len);
    // Exited instance first (rowOrder), untouched.
    try std.testing.expect(snap2.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 700), snap2.rows[0].sent);
    try std.testing.expect(!snap2.rows[1].exited);
    try std.testing.expectEqualStrings("\\x\\b.exe", snap2.rows[1].name);
    try std.testing.expectEqual(@as(u64, 11), snap2.rows[1].sent);
}

test "traffic just after exit attributes to the exited row, never a fresh one" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"));
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""));
    // Flush-window straggler: stamped while the process was alive.
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 333, 1, 180));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 333), snap.rows[0].recv);

    // Even once the PID is reused, an event stamped before the new
    // instance existed still belongs to the exited row.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"));
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 44, 1, 190));
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 55, 1, 600));
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(u64, 333 + 44), snap2.rows[0].recv);
    try std.testing.expectEqual(@as(u64, 55), snap2.rows[1].recv);
}

test "a stop with no prior identity yields an unnamed exited row that catches late traffic" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // The process exited before the rundown burst could name it. The stop
    // payload's ANSI name never reaches the record (parser contract), so the
    // row stays nameless rather than showing a truncated name.
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""));
    try core.applyEvent(testEventAt(.send, .tcp, 100, 77, 1, 150));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqualStrings("", snap.rows[0].name);
    try std.testing.expectEqual(@as(u64, 77), snap.rows[0].sent);
}

test "a start for an already-owned PID retires the unseen predecessor" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"));
    try core.applyEvent(testEventAt(.send, .tcp, 100, 900, 1, 150));
    // The stop was lost; the next instance's start must not merge into a.exe.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"));
    try core.applyEvent(testEventAt(.send, .tcp, 100, 1, 1, 600));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 2), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 900), snap.rows[0].sent);
    try std.testing.expectEqual(@as(u64, 1), snap.rows[1].sent);
}

test "display names are drive-letter converted; bare kernel names pass through" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    const entries = try gpa.alloc(device_map.DriveMap.Entry, 1);
    entries[0] = .{ .device = try gpa.dupe(u8, "\\Device\\HarddiskVolume3"), .letter = 'C' };
    core.drive_map = .{ .entries = entries };

    try core.applyProcess(procEvent(.rundown, 100, 111, 0, "\\Device\\HarddiskVolume3\\Windows\\System32\\PING.EXE"));
    try core.applyProcess(procEvent(.rundown, 4, 1, 0, "System"));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqualStrings(
        "C:\\Windows\\System32\\PING.EXE",
        rowForPid(snap.rows, 100).?.name,
    );
    try std.testing.expectEqualStrings("System", rowForPid(snap.rows, 4).?.name);
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

    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"));
    try core.applyEvent(testEventAt(.send, .tcp, 100, 1000, 51000, 150));
    published.publish(try core.buildSnapshot());
    const held = published.acquire().?;
    defer held.release();

    // The Engine moves on: more bytes, an exit, a new PID, loss, a new
    // Snapshot.
    try core.applyEvent(testEventAt(.send, .tcp, 100, 5000, 51000, 160));
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""));
    try core.applyEvent(testEvent(.recv, .tcp, 777, 1, 4000));
    _ = core.noteLoss(9, 0);
    core.flagRebaselined();
    published.publish(try core.buildSnapshot());

    // The held reader still sees the old world, bit for bit.
    try std.testing.expectEqual(@as(usize, 1), held.rows.len);
    try std.testing.expectEqual(@as(u64, 1000), held.rows[0].sent);
    try std.testing.expect(!held.rows[0].exited);
    try std.testing.expectEqualStrings("\\x\\a.exe", held.rows[0].name);
    try std.testing.expect(!held.health.rebaselined);

    // A fresh reader sees the new one.
    const fresh = published.acquire().?;
    defer fresh.release();
    try std.testing.expect(fresh.seq > held.seq);
    try std.testing.expectEqual(@as(u64, 6000), rowForPid(fresh.rows, 100).?.sent);
    try std.testing.expect(rowForPid(fresh.rows, 100).?.exited);
    try std.testing.expect(fresh.health.rebaselined);
}
