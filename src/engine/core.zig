//! The Engine thread's single-threaded state (ADR-0002: one owner, no
//! locks). Rows are process instances keyed (PID, payload CreateTime) —
//! PID reuse yields a fresh row, exited rows persist all session with their
//! In-session Totals intact, and traffic arriving inside the flush window
//! after an exit still lands on the exited row (issue #21). The Flow layer
//! (flows.zig, issue #22) hangs each row's Flows beneath it: Flows bind to
//! their owning row instance at open, close into Linger on disconnect,
//! age-out, sweep, or process exit, and reconcile against IP Helper
//! snapshots. The unified loss recovery — ring overflow and ETW EventsLost
//! both re-baseline from fresh tables and set the sticky health flag.
//! Totals are honest or marked, never silently low. All lifecycle timing
//! runs on the caller's monotonic `now_ms` so the whole layer is drivable
//! by synthetic clocks.

const std = @import("std");
const device_map = @import("device_map.zig");
const event = @import("event.zig");
const flows = @import("flows.zig");
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
    /// In-session Totals: independent accumulators — they include bytes of
    /// Flows that have long left the list.
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
    flows: flows.Table = .{},
    /// NT-device → drive-letter display conversion. Populated by the runner
    /// at start; owned (and freed) by Core.
    drive_map: device_map.DriveMap = .{},
    health: snapshot.Health = .{},
    seq: u64 = 0,
    /// Publish at least once even before any traffic.
    dirty: bool = true,
    /// Scratch flow-entry list reused across snapshot builds.
    flow_scratch: std.ArrayList(flows.Entry) = .empty,

    pub fn init(gpa: std.mem.Allocator) Core {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Core) void {
        for (self.rows.items) |row| self.gpa.free(row.name);
        self.rows.deinit(self.gpa);
        self.live_by_pid.deinit(self.gpa);
        self.exited_by_pid.deinit(self.gpa);
        self.flows.deinit(self.gpa);
        self.drive_map.deinit(self.gpa);
        self.flow_scratch.deinit(self.gpa);
    }

    /// Apply one net-event ring record. OOM drops the record — the caller
    /// counts it as ring-equivalent loss.
    pub fn applyEvent(
        self: *Core,
        ev: event.NetEvent,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        switch (ev.op) {
            .send, .recv => {
                if (ev.proto == .icmp) return self.applyIcmp(ev, now_ms);
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                const row = &self.rows.items[idx];
                if (ev.op == .send)
                    row.sent += ev.size
                else
                    row.recv += ev.size;
                // First activity opens the Flow (raced the table snapshot,
                // or a new Generation after closure).
                const live = try self.flows.touch(self.gpa, flows.flowKey(ev), idx, now_ms);
                if (ev.op == .send)
                    live.counts.sent += ev.size
                else
                    live.counts.recv += ev.size;
                self.dirty = true;
            },
            .connect => {
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                try self.flows.connect(self.gpa, flows.flowKey(ev), idx, now_ms);
                self.dirty = true;
            },
            .disconnect => {
                if (try self.flows.close(self.gpa, flows.flowKey(ev), now_ms))
                    self.dirty = true;
            },
        }
    }

    /// ICMP's own accounting (issue #27). Nothing here touches a byte total:
    /// no user-mode source reports ICMP message sizes, so ICMP Flows count
    /// messages and In-session Totals stay pure bytes.
    ///
    /// Outbound messages carry the real caller in the event-header PID and
    /// open or refresh that process's ICMP Flow. Inbound messages carry no
    /// attribution whatsoever — they are correlated to the Flow whose process
    /// most recently sent the request they pair with, and **dropped entirely**
    /// when nothing matches: unsolicited inbound ICMP must leave no trace
    /// anywhere, not even a Process Row (spec issue #18 Capture: ICMP).
    /// ICMP has no lifecycle events, so `ev.op` is only ever send or recv
    /// here — the caller's switch already narrowed it.
    fn applyIcmp(self: *Core, ev: event.NetEvent, now_ms: u64) error{OutOfMemory}!void {
        if (ev.op == .send) {
            const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
            const live = try self.flows.touch(self.gpa, flows.flowKey(ev), idx, now_ms);
            live.counts.msgs_sent += 1;
            notePeer(live, ev.remote_addr);
            try self.flows.noteIcmpRequest(self.gpa, ev.family, ev.icmp_type, ev.pid);
            self.dirty = true;
            return;
        }
        const live = self.flows.matchIcmpReply(ev.family, ev.icmp_type, now_ms) orelse return;
        live.counts.msgs_recv += 1;
        notePeer(live, ev.remote_addr);
        self.dirty = true;
    }

    /// Learn an ICMP Flow's peer from whichever message names one. Under this
    /// session's keyword only replies do (ADR-0003), which is why the peer is
    /// unknown until one arrives — but a build whose send path logs addresses
    /// would name it on the first request instead, so take it from either.
    /// Latest wins: the Flow shows who it is talking to now.
    fn notePeer(live: anytype, remote_addr: [16]u8) void {
        if (std.mem.allEqual(u8, &remote_addr, 0)) return;
        live.icmp_remote = remote_addr;
    }

    /// Apply one Kernel-Process ring record: row identity and lifetime.
    pub fn applyProcess(
        self: *Core,
        ev: event.ProcessEvent,
        now_ms: u64,
    ) error{OutOfMemory}!void {
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
                        try self.retire(idx, 0, now_ms);
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
                        try self.retire(idx, ev.exit_time, now_ms);
                        self.dirty = true;
                    }
                    // A stop for some other instance of this PID: the row it
                    // describes was already retired (or never known) — the
                    // exit-time backfill below still applies.
                } else {
                    // No row at all (exited before the rundown burst landed):
                    // an exited row keyed from the stop payload keeps any
                    // late traffic attributed. Name stays empty.
                    try self.retire(try self.newRow(ev.pid, ev.create_time), ev.exit_time, now_ms);
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

    /// flows.Table asks here for the owning row of a Flow it is about to
    /// seed — only then, so skipped table rows can't mint ghost placeholder
    /// rows.
    pub fn rowForSeed(self: *Core, pid: u32) error{OutOfMemory}!u32 {
        return self.rowForTraffic(pid, 0);
    }

    /// Append a row and make it the PID's current owner.
    fn newRow(self: *Core, pid: u32, create_time: u64) error{OutOfMemory}!u32 {
        const idx: u32 = @intCast(self.rows.items.len);
        try self.rows.append(self.gpa, .{ .pid = pid, .create_time = create_time });
        try self.live_by_pid.put(self.gpa, pid, idx);
        return idx;
    }

    /// Mark a row exited and stop routing its PID to it (except through
    /// exited_by_pid, for the flush window). Process exit closes the
    /// instance's live Flows into normal Linger (spec issue #18 Data model)
    /// — the issue #22 seam, wired here to the Kernel-Process events.
    fn retire(self: *Core, idx: u32, exit_time: u64, now_ms: u64) error{OutOfMemory}!void {
        const row = &self.rows.items[idx];
        row.exited = true;
        row.exit_time = exit_time;
        _ = self.live_by_pid.remove(row.pid);
        try self.exited_by_pid.put(self.gpa, row.pid, idx);
        _ = try self.flows.closeRowFlows(self.gpa, idx, now_ms);
    }

    /// Set a row's display name from a start/rundown payload, first writer
    /// wins (start and rundown carry the same name).
    fn nameRow(self: *Core, idx: u32, ev: event.ProcessEvent) error{OutOfMemory}!void {
        if (ev.name_len == 0 or self.rows.items[idx].name.len != 0) return;
        var buf: [3 * event.max_image_name_units]u8 = undefined;
        const n = std.unicode.wtf16LeToWtf8(&buf, ev.name());
        self.rows.items[idx].name = try self.drive_map.displayPath(self.gpa, buf[0..n]);
    }

    /// Time-driven Flow maintenance: Linger expiry and UDP age-outs. Called
    /// at the Engine's flush-tick cadence.
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
        if (try self.flows.reconcile(self.gpa, rows, self, now_ms)) self.dirty = true;
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
    /// one row per process instance (live, exited, and placeholders), sorted
    /// by PID with exited instances before their PID's live successor, each
    /// row's Flows grouped under it.
    pub fn buildSnapshot(self: *Core) error{OutOfMemory}!*snapshot.Snapshot {
        // Flows first, sorted (row, identity, generation): each row's Flows
        // become one contiguous, deterministically ordered span.
        self.flow_scratch.clearRetainingCapacity();
        try self.flows.collect(self.gpa, &self.flow_scratch);
        std.mem.sort(flows.Entry, self.flow_scratch.items, {}, entryLessThan);

        const snap = try snapshot.create(
            self.gpa,
            self.rows.items.len,
            self.flow_scratch.items.len,
        );
        errdefer snap.release();
        const out = snapshot.mutableRows(snap);
        const flat = snapshot.mutableFlows(snap);

        for (self.rows.items, out) |row, *dst| {
            dst.* = .{
                .pid = row.pid,
                .name = try snapshot.arenaDupe(snap, row.name),
                .exited = row.exited,
                .sent = row.sent,
                .recv = row.recv,
            };
        }
        // Flows address rows by position — attach spans and count live
        // flows before sorting (the sorted rows carry their slices along).
        for (self.flow_scratch.items, 0..) |e, i| flat[i] = e.flow;
        var fi: usize = 0;
        while (fi < self.flow_scratch.items.len) {
            const start = fi;
            const row_idx = self.flow_scratch.items[fi].row;
            const dst = &out[row_idx];
            while (fi < self.flow_scratch.items.len and
                self.flow_scratch.items[fi].row == row_idx) : (fi += 1)
            {
                const f = self.flow_scratch.items[fi].flow;
                if (!f.lingering) switch (f.proto) {
                    .tcp => dst.tcp_conns += 1,
                    .udp => dst.udp_socks += 1,
                    .icmp => dst.icmp_flows += 1,
                };
            }
            dst.flows = flat[start..fi];
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

/// Sort order for snapshot flows: owning row, then flow identity, then
/// Generation — stable across builds so the UI never sees flows jump.
fn entryLessThan(_: void, a: flows.Entry, b: flows.Entry) bool {
    if (a.row != b.row) return a.row < b.row;
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
        .icmp_type = 0,
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

test "start and rundown for the same instance dedupe on the row key" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\ping.exe"), 0);
    try core.applyProcess(procEvent(.rundown, 100, 111, 0, "\\x\\ping.exe"), 0);

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
    try core.applyEvent(testEvent(.send, .tcp, 100, 5000, 1), 0);
    try core.applyProcess(procEvent(.rundown, 100, 111, 0, "\\x\\svchost.exe"), 0);

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
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"), 0);
    try core.applyEvent(testEventAt(.send, .tcp, 100, 700, 1, 150), 0);
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""), 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 700), snap.rows[0].sent);
    try std.testing.expectEqualStrings("\\x\\a.exe", snap.rows[0].name);

    // The PID comes back as a different process: fresh row, fresh totals.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"), 0);
    try core.applyEvent(testEventAt(.send, .tcp, 100, 11, 1, 600), 0);
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
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"), 0);
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""), 0);
    // Flush-window straggler: stamped while the process was alive.
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 333, 1, 180), 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 333), snap.rows[0].recv);

    // Even once the PID is reused, an event stamped before the new
    // instance existed still belongs to the exited row.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"), 0);
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 44, 1, 190), 0);
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 55, 1, 600), 0);
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
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""), 0);
    try core.applyEvent(testEventAt(.send, .tcp, 100, 77, 1, 150), 0);

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
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\a.exe"), 0);
    try core.applyEvent(testEventAt(.send, .tcp, 100, 900, 1, 150), 0);
    // The stop was lost; the next instance's start must not merge into a.exe.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"), 0);
    try core.applyEvent(testEventAt(.send, .tcp, 100, 1, 1, 600), 0);

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

    try core.applyProcess(procEvent(.rundown, 100, 111, 0, "\\Device\\HarddiskVolume3\\Windows\\System32\\PING.EXE"), 0);
    try core.applyProcess(procEvent(.rundown, 4, 1, 0, "System"), 0);

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

test "process exit closes its live Flows into normal Linger" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .tcp, 100, 50, 51000), 0);
    try core.applyEvent(testEvent(.send, .udp, 100, 5, 5353), 0);
    try core.applyEvent(testEvent(.send, .tcp, 200, 9, 52000), 0);

    // The Kernel-Process stop event adopts the traffic placeholder and
    // retires it — closing the instance's live Flows on the way out.
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""), 1000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const exited = rowForPid(snap.rows, 100).?;
    try std.testing.expect(exited.exited);
    try std.testing.expectEqual(@as(usize, 2), exited.flows.len);
    try std.testing.expect(exited.flows[0].lingering);
    try std.testing.expect(exited.flows[1].lingering);
    try std.testing.expectEqual(@as(u64, 55), exited.sent);
    try std.testing.expect(!rowForPid(snap.rows, 200).?.flows[0].lingering);

    // Normal Linger: gone at 10 s, the exited row and its totals stay.
    try core.tick(11_000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 0), row2.flows.len);
    try std.testing.expectEqual(@as(u64, 55), row2.sent);
}

// ---------------------------------------------------------------------------
// ICMP (issue #27). Outbound messages arrive attributed by the event-header
// PID; inbound ones arrive with no attribution at all (pid 0) and must be
// correlated here or dropped.
// ---------------------------------------------------------------------------

const echo_request: u8 = 8;
const echo_reply: u8 = 0;
const echo_request6: u8 = 128;
const echo_reply6: u8 = 129;
const ttl_exceeded: u8 = 11;

const host_a = [4]u8{ 1, 1, 1, 1 };
const host_b = [4]u8{ 8, 8, 8, 8 };

/// An outbound ICMP message from `pid`. The send path logs no addresses
/// (ADR-0003), so there is deliberately no remote to pass.
fn icmpSend(pid: u32, icmp_type: u8) event.NetEvent {
    return icmpSendAt(pid, icmp_type, .v4, 0);
}

fn icmpSendAt(pid: u32, icmp_type: u8, family: event.Family, ts: i64) event.NetEvent {
    return .{
        .op = .send,
        .proto = .icmp,
        .family = family,
        .icmp_type = icmp_type,
        .pid = pid,
        .size = 0,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .timestamp_ft = ts,
    };
}

/// An inbound ICMP message: no PID, but a real peer address.
fn icmpRecv(icmp_type: u8, remote: []const u8) event.NetEvent {
    return icmpRecvFamily(icmp_type, .v4, remote);
}

fn icmpRecvFamily(icmp_type: u8, family: event.Family, remote: []const u8) event.NetEvent {
    var ev = icmpSendAt(0, icmp_type, family, 0);
    ev.op = .recv;
    @memcpy(ev.remote_addr[0..remote.len], remote);
    return ev;
}

test "a ping run is one ICMP Flow with request and reply message counts" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\PING.EXE"), 0);
    // `ping -n 3 1.1.1.1`: three requests out, three replies back.
    var t: u64 = 0;
    while (t < 3) : (t += 1) {
        try core.applyEvent(icmpSend(100, echo_request), t * 1000);
        try core.applyEvent(icmpRecv(echo_reply, &host_a), t * 1000 + 5);
    }

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    const f = row.flows[0];
    try std.testing.expectEqual(event.Proto.icmp, f.proto);
    try std.testing.expectEqual(@as(u64, 3), f.msgs_sent);
    try std.testing.expectEqual(@as(u64, 3), f.msgs_recv);
    try std.testing.expect(!f.lingering);
    try std.testing.expectEqual(@as(u32, 1), row.icmp_flows);
    // The peer is unknown on the send path; the replies name it.
    try std.testing.expectEqualSlices(u8, &host_a, f.remote_addr[0..4]);
    // ICMP contributes zero to every byte total, at both levels.
    try std.testing.expectEqual(@as(u64, 0), f.sent + f.recv);
    try std.testing.expectEqual(@as(u64, 0), row.sent + row.recv);
}

test "unsolicited inbound ICMP creates no Flow, no row, no activity anywhere" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Nobody asked: an echo reply, a timestamp reply, and an inbound echo
    // *request* (someone pinging us) all arrive out of nowhere.
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 0);
    try core.applyEvent(icmpRecv(14, &host_a), 0);
    try core.applyEvent(icmpRecv(echo_request, &host_a), 0);
    try core.applyEvent(icmpRecvFamily(echo_reply6, .v6, &host_a), 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    // Not even a placeholder Process Row — System must gain nothing.
    try std.testing.expectEqual(@as(usize, 0), snap.rows.len);
    try std.testing.expectEqual(@as(usize, 0), snap.flows.len);
}

test "a reply whose type pairs with nothing is dropped even mid-conversation" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(icmpSend(100, echo_request), 0);
    // What traceroute sees: the hop answers TTL-exceeded, not an echo reply.
    // Pairing with nothing, it is the documented blind spot — dropped.
    try core.applyEvent(icmpRecv(ttl_exceeded, &host_a), 10);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u64, 1), row.flows[0].msgs_sent);
    try std.testing.expectEqual(@as(u64, 0), row.flows[0].msgs_recv);
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
}

test "two concurrent pingers resolve replies to the most recent requester" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(icmpSend(100, echo_request), 0);
    try core.applyEvent(icmpSend(200, echo_request), 10);
    // Event 1422 carries no echo Identifier, so the reply can only go to the
    // most recent requester — the documented heuristic.
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 20);
    // …and it moves with the next request.
    try core.applyEvent(icmpSend(100, echo_request), 30);
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 40);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const first = rowForPid(snap.rows, 100).?;
    const second = rowForPid(snap.rows, 200).?;
    try std.testing.expectEqual(@as(u64, 2), first.flows[0].msgs_sent);
    try std.testing.expectEqual(@as(u64, 1), first.flows[0].msgs_recv);
    try std.testing.expectEqual(@as(u64, 1), second.flows[0].msgs_sent);
    try std.testing.expectEqual(@as(u64, 1), second.flows[0].msgs_recv);
    // Both pingers stay visible as their own Flows — no merging.
    try std.testing.expectEqual(@as(u32, 1), first.icmp_flows);
    try std.testing.expectEqual(@as(u32, 1), second.icmp_flows);
}

test "ICMPv6 echo pairs on its own type numbers, separately from v4" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // A v4 and a v6 ping from the same process are two Flows, and neither
    // family's replies may land on the other.
    try core.applyEvent(icmpSendAt(100, echo_request, .v4, 0), 0);
    try core.applyEvent(icmpSendAt(100, echo_request6, .v6, 0), 0);
    try core.applyEvent(icmpRecvFamily(echo_reply6, .v6, &.{}), 10);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 2), row.flows.len);
    try std.testing.expectEqual(@as(u32, 2), row.icmp_flows);
    for (row.flows) |f| {
        try std.testing.expectEqual(@as(u64, 1), f.msgs_sent);
        const want: u64 = if (f.family == .v6) 1 else 0;
        try std.testing.expectEqual(want, f.msgs_recv);
    }
}

test "one process pinging two hosts is one ICMP Flow showing its latest peer" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // ICMP identity is (protocol, family, PID): the send path names no peer,
    // so per-host Flows cannot exist (ADR-0003).
    try core.applyEvent(icmpSend(100, echo_request), 0);
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 10);
    try core.applyEvent(icmpSend(100, echo_request), 20);
    try core.applyEvent(icmpRecv(echo_reply, &host_b), 30);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expectEqual(@as(u64, 2), row.flows[0].msgs_recv);
    try std.testing.expectEqualSlices(u8, &host_b, row.flows[0].remote_addr[0..4]);
    // No local endpoint, no ports — the identity has none to show.
    try std.testing.expectEqual(@as(u16, 0), row.flows[0].local_port);
    try std.testing.expectEqual(@as(u16, 0), row.flows[0].remote_port);
    try std.testing.expectEqualSlices(
        u8,
        &@as([16]u8, @splat(0)),
        &row.flows[0].local_addr,
    );
}

test "ICMP the kernel itself sends is System's Flow, not phantom activity" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // The stack originates ICMP of its own — errors, neighbor discovery, and
    // the echo replies it sends when something pings this machine — and logs
    // them in System's context. Observed live: a PID-4 Flow reading
    // "1 sent / 0 recv" with no peer. That is a real outbound message, so it
    // is shown; the rule that keeps System clean is about *inbound* messages,
    // which carry no attribution and are dropped when unmatched.
    try core.applyEvent(icmpSend(4, 3), 0); // destination unreachable
    // …and nothing pairs with it, so no reply can ever land on it.
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 10);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    const row = rowForPid(snap.rows, 4).?;
    try std.testing.expectEqual(@as(u64, 1), row.flows[0].msgs_sent);
    try std.testing.expectEqual(@as(u64, 0), row.flows[0].msgs_recv);
    try std.testing.expectEqual(@as(u64, 0), row.sent + row.recv);
    // No peer: the send path names none (ADR-0003).
    try std.testing.expectEqualSlices(
        u8,
        &@as([16]u8, @splat(0)),
        &row.flows[0].remote_addr,
    );
}

test "a send that does name its peer sets it without waiting for a reply" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // This session's keyword logs no send-path addresses, but 1809 may and
    // the parser passes through whatever is there: an unanswered ping should
    // then still show its target.
    var ev = icmpSend(100, echo_request);
    @memcpy(ev.remote_addr[0..4], &host_a);
    try core.applyEvent(ev, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const f = rowForPid(snap.rows, 100).?.flows[0];
    try std.testing.expectEqual(@as(u64, 1), f.msgs_sent);
    try std.testing.expectEqual(@as(u64, 0), f.msgs_recv);
    try std.testing.expectEqualSlices(u8, &host_a, f.remote_addr[0..4]);
}

test "ICMP Flows age out after 30 s inactivity into normal Linger" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(icmpSend(100, echo_request), 0);
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 5_000); // activity resets it

    try core.tick(34_999);
    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expect(!rowForPid(snap.rows, 100).?.flows[0].lingering);

    try core.tick(35_000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 100).?;
    try std.testing.expect(row2.flows[0].lingering);
    try std.testing.expectEqual(@as(u32, 0), row2.icmp_flows);
    // The counts stay readable while it Lingers.
    try std.testing.expectEqual(@as(u64, 1), row2.flows[0].msgs_sent);
    try std.testing.expectEqual(@as(u64, 1), row2.flows[0].msgs_recv);
    try std.testing.expectEqualSlices(u8, &host_a, row2.flows[0].remote_addr[0..4]);

    // …and 10 s later it leaves the list entirely.
    try core.tick(45_000);
    const snap3 = try core.buildSnapshot();
    defer snap3.release();
    try std.testing.expectEqual(@as(usize, 0), rowForPid(snap3.rows, 100).?.flows.len);
}

test "a reply arriving after its Flow ended is dropped, never revived" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(icmpSend(100, echo_request), 0);
    try core.tick(30_000); // aged out into Linger

    // Lingering is not live: the late reply must not resurrect it.
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 30_100);
    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u64, 0), row.flows[0].msgs_recv);

    // Once the Linger window closes the slot is gone; still no revival.
    try core.tick(41_000);
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 41_100);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(usize, 0), rowForPid(snap2.rows, 100).?.flows.len);
}

test "the reconciliation sweep never closes an ICMP Flow" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(icmpSend(100, echo_request), 0);
    // ICMP has no IP Helper owner table, so an empty sweep says nothing about
    // it — only the 30 s age-out ends an ICMP Flow.
    try core.reconcile(&.{}, 5_000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expect(!row.flows[0].lingering);
    try std.testing.expectEqual(@as(u32, 1), row.icmp_flows);

    // And a TCP sweep alongside it still does its own job.
    const tcp = testEvent(.send, .tcp, 100, 10, 51000);
    try core.applyEvent(tcp, 6_000);
    try core.reconcile(&.{}, 7_000);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 100).?;
    try std.testing.expectEqual(@as(u32, 1), row2.icmp_flows);
    try std.testing.expectEqual(@as(u32, 0), row2.tcp_conns);
}

test "a ping process exiting closes its ICMP Flow into normal Linger" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // The common case: ping.exe exits seconds after its last reply.
    try core.applyProcess(procEvent(.start, 100, 111, 0, "\\x\\PING.EXE"), 0);
    try core.applyEvent(icmpSend(100, echo_request), 0);
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 10);
    try core.applyProcess(procEvent(.stop, 100, 111, 200, ""), 1_000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expect(row.exited);
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u32, 0), row.icmp_flows);
    try std.testing.expectEqual(@as(u64, 1), row.flows[0].msgs_recv);

    // A straggler reply after the exit has no live Flow to land on.
    try core.applyEvent(icmpRecv(echo_reply, &host_a), 1_100);
    const snap2 = try core.buildSnapshot();
    defer snap2.release();
    try std.testing.expectEqual(@as(u64, 1), rowForPid(snap2.rows, 100).?.flows[0].msgs_recv);
}

test "ICMP alongside TCP and UDP leaves byte totals untouched" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.send, .tcp, 100, 1500, 51000), 0);
    try core.applyEvent(testEvent(.recv, .udp, 100, 40, 5353), 0);
    var t: u64 = 0;
    while (t < 50) : (t += 1) try core.applyEvent(icmpSend(100, echo_request), 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u64, 1500), row.sent);
    try std.testing.expectEqual(@as(u64, 40), row.recv);
    try std.testing.expectEqual(@as(u32, 1), row.icmp_flows);
    // Every flow's bytes and messages stay in their own columns.
    var bytes: u64 = 0;
    var msgs: u64 = 0;
    for (row.flows) |f| {
        bytes += f.sent + f.recv;
        msgs += f.msgs_sent + f.msgs_recv;
    }
    try std.testing.expectEqual(@as(u64, 1540), bytes);
    try std.testing.expectEqual(@as(u64, 50), msgs);
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
