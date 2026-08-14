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
//! Totals are honest or marked, never silently low. Rates (issue #23) ride
//! alongside: every byte is bucketed twice at event time, once on its Flow
//! and once on its Row, so a Row's speed outlives its Flows. The memory
//! caps run on the same tick — Flows at flows.cap, exited rows at
//! `exited_row_cap` — and both obey the one rule that matters: eviction may
//! coarsen attribution, never lose bytes. All lifecycle timing runs on the
//! caller's monotonic `now_ms` so the whole layer is drivable by synthetic
//! clocks.

const std = @import("std");
const device_map = @import("device_map.zig");
const event = @import("event.zig");
const flows = @import("flows.zig");
const hostnames = @import("hostnames.zig");
const rates = @import("rates.zig");
const reverse_lookup = @import("reverse_lookup.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

/// The exited-row cap (spec issue #18 Data model, "Memory bounds"): at most
/// this many exited Process Rows stay individually visible. Live rows are
/// never capped — the machine's own process count bounds them.
pub const exited_row_cap: usize = 512;
/// The label the Evicted-processes Row carries (CONTEXT.md).
pub const evicted_processes_name = "(evicted processes)";
/// How often the Flow list is walked for name maintenance: cache refreshes
/// and reverse-lookup candidates. Well under the 2 s grace, and far cheaper
/// than doing either on the per-event path.
const name_maintenance_ms: u64 = 500;

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
    /// The Row's own event-time rate ring, bucketed alongside its Flows'
    /// (spec issue #18: double-bucketed, so Row speed survives Flow
    /// eviction).
    rate: rates.Ring = .{},
    /// This is the Evicted-processes Row (CONTEXT.md): where the totals of
    /// exited rows the cap took land. Never a PID, never a victim.
    evicted_processes: bool = false,
};

pub const Core = struct {
    gpa: std.mem.Allocator,
    /// All Process Rows. Flows address their owner by index here, and rows
    /// only ever move in `evictRows`, which renumbers every reference in the
    /// same breath — nothing else may reorder or remove them.
    rows: std.ArrayList(ProcessRow) = .empty,
    /// The row currently owning each PID (live, or a placeholder).
    live_by_pid: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    /// The most recently exited row per PID — where post-exit flush-window
    /// traffic goes.
    exited_by_pid: std.AutoHashMapUnmanaged(u32, u32) = .empty,
    flows: flows.Table = .{},
    /// The tiered address→name cache a Flow consults once, at creation.
    names: hostnames.Table = .{},
    /// The reverse-lookup lane, when one is running. Null leaves unnamed
    /// Flows showing their bare endpoints — which is what the Engine does
    /// anyway until a lookup lands.
    reverse: ?*reverse_lookup.Lane = null,
    /// NT-device → drive-letter display conversion. Populated by the runner
    /// at start; owned (and freed) by Core.
    drive_map: device_map.DriveMap = .{},
    health: snapshot.Health = .{},
    seq: u64 = 0,
    /// Publish at least once even before any traffic.
    dirty: bool = true,
    /// Scratch flow-entry list reused across snapshot builds.
    flow_scratch: std.ArrayList(flows.Entry) = .empty,
    /// Scratch reverse-lookup candidate list, reused across maintenance passes.
    reverse_scratch: std.ArrayList(event.IpAddr) = .empty,
    last_name_maintenance_ms: u64 = 0,

    pub fn init(gpa: std.mem.Allocator) Core {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Core) void {
        for (self.rows.items) |row| self.gpa.free(row.name);
        self.rows.deinit(self.gpa);
        self.live_by_pid.deinit(self.gpa);
        self.exited_by_pid.deinit(self.gpa);
        self.flows.deinit(self.gpa);
        self.names.deinit(self.gpa);
        self.drive_map.deinit(self.gpa);
        self.flow_scratch.deinit(self.gpa);
        self.reverse_scratch.deinit(self.gpa);
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
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                const sent: u64 = if (ev.op == .send) ev.size else 0;
                const recv: u64 = if (ev.op == .recv) ev.size else 0;
                // Rates bucket by event time, never arrival time — a flush
                // burst delivers a second's records in one drain.
                const at = eventMs(ev.timestamp_ft);
                const row = &self.rows.items[idx];
                row.sent += sent;
                row.recv += recv;
                row.rate.add(at, sent, recv);
                // First activity opens the Flow (raced the table snapshot,
                // or a new Generation after closure).
                const live = try self.flows.touch(
                    self.gpa,
                    flows.flowKey(ev),
                    idx,
                    now_ms,
                    &self.names,
                );
                live.sent += sent;
                live.recv += recv;
                live.rate.add(at, sent, recv);
                self.dirty = true;
            },
            .connect => {
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                try self.flows.connect(self.gpa, flows.flowKey(ev), idx, now_ms, &self.names);
                self.dirty = true;
            },
            .disconnect => {
                if (try self.flows.close(self.gpa, flows.flowKey(ev), now_ms))
                    self.dirty = true;
            },
        }
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
        // The PID is up for reuse: drop what only this process observed, so
        // the next holder cannot inherit its names (research §5). Flows
        // already open keep the name they were attributed at creation.
        self.names.forgetPid(self.gpa, row.pid);
    }

    /// Set a row's display name from a start/rundown payload, first writer
    /// wins (start and rundown carry the same name).
    fn nameRow(self: *Core, idx: u32, ev: event.ProcessEvent) error{OutOfMemory}!void {
        if (ev.name_len == 0 or self.rows.items[idx].name.len != 0) return;
        var buf: [3 * event.max_image_name_units]u8 = undefined;
        const n = std.unicode.wtf16LeToWtf8(&buf, ev.name());
        self.rows.items[idx].name = try self.drive_map.displayPath(self.gpa, buf[0..n]);
    }

    /// Apply one accepted DNS-Client 3008 record: the name this process
    /// resolved, for every address the answer carried (spec issue #18
    /// "Capture: hostname observation"). Flows already open to those
    /// addresses upgrade in place.
    pub fn applyDns(
        self: *Core,
        ev: event.DnsEvent,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        // A nameless observation would occupy the global tier without naming
        // anything — and, worse, suppress the reverse lookup that would have.
        if (ev.name_len == 0) return;
        const name: hostnames.Name = .{
            .text = ev.name(),
            .alias = ev.alias(),
            .origin = .observed,
        };
        for (ev.addresses()) |ip| {
            try self.names.observe(self.gpa, ev.pid, ip, name, now_ms);
            if (try self.flows.applyName(self.gpa, ip, name)) self.dirty = true;
        }
    }

    /// Time-driven maintenance: Linger expiry, UDP age-outs, the memory caps,
    /// and the Hostname Attribution upkeep — reverse-lookup results in,
    /// candidates out, idle cache entries expired. Called at the Engine's
    /// flush-tick cadence, so the caps are enforced within a tick of being
    /// crossed rather than per event.
    ///
    /// Naming runs last, after the caps: a Flow the cap just took must not be
    /// queued for a lookup whose result would have nowhere to land.
    pub fn tick(self: *Core, now_ms: u64) error{OutOfMemory}!void {
        if (try self.flows.tick(self.gpa, now_ms)) self.dirty = true;
        if (try self.flows.evict(self.gpa)) self.dirty = true;
        if (try self.evictRows()) self.dirty = true;
        if (self.reverse) |lane| {
            while (lane.popResult()) |result| try self.applyReverse(result, now_ms);
        }
        if (now_ms -| self.last_name_maintenance_ms >= name_maintenance_ms) {
            self.last_name_maintenance_ms = now_ms;
            try self.maintainNames(now_ms);
        }
    }

    /// One finished reverse lookup. A name enters the hint tier and un-bares
    /// the Flows waiting on it; a proven absence enters the negative cache, so
    /// the address is left alone for the next ten minutes. A lookup that
    /// simply did not complete records nothing — that is a fact about the
    /// resolver, not the address, and the next pass will ask again.
    fn applyReverse(
        self: *Core,
        result: reverse_lookup.Result,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        self.names.clearPending(result.ip);
        switch (result.answer) {
            .named => {
                const name: hostnames.Name = .{ .text = result.name(), .origin = .reverse };
                try self.names.noteHint(self.gpa, result.ip, name, now_ms);
                if (try self.flows.applyName(self.gpa, result.ip, name)) self.dirty = true;
            },
            .no_record => try self.names.noteMissing(self.gpa, result.ip, now_ms),
            .failed => {},
        }
    }

    fn maintainNames(self: *Core, now_ms: u64) error{OutOfMemory}!void {
        self.reverse_scratch.clearRetainingCapacity();
        const collected = self.flows.maintainNames(
            self.gpa,
            &self.names,
            now_ms,
            &self.reverse_scratch,
        );
        // Candidates come out already claimed, so queue-or-release has to run
        // even when collection ran out of memory partway: an address left
        // claimed is never asked about and never named again.
        for (self.reverse_scratch.items) |ip| {
            const queued = if (self.reverse) |lane| lane.request(ip) else false;
            if (!queued) self.names.clearPending(ip);
        }
        try collected;
        self.names.sweep(self.gpa, now_ms);
    }

    /// Enforce the exited-row cap (CONTEXT.md "Eviction"): the least
    /// informative exited rows — smallest totals first, oldest first among
    /// equals — hand their In-session Totals to the single "(evicted
    /// processes)" row and leave the table with their Flows. Live rows are
    /// never candidates, and no byte moves anywhere but upward.
    ///
    /// Rows are addressed by index (Flows bind to their owner at open), so
    /// removing any means renumbering the survivors everywhere they are
    /// named. Every allocation the round needs is taken before the first
    /// change lands, so a failed round changes nothing and the next tick
    /// retries.
    fn evictRows(self: *Core) error{OutOfMemory}!bool {
        const gpa = self.gpa;
        var capped: usize = 0;
        for (self.rows.items) |r| {
            if (cappedRow(r)) capped += 1;
        }
        if (capped <= exited_row_cap) return false;

        const candidates = try gpa.alloc(u32, capped);
        defer gpa.free(candidates);
        var n: usize = 0;
        for (self.rows.items, 0..) |r, idx| {
            if (cappedRow(r)) {
                candidates[n] = @intCast(idx);
                n += 1;
            }
        }
        std.mem.sort(u32, candidates, self.rows.items, leastInformativeFirst);
        const victims = candidates[0 .. capped - exited_row_cap];

        // Appending it before the map is built keeps it a survivor like
        // any other row.
        const sink = try self.evictedProcessesRow();
        const map = try gpa.alloc(u32, self.rows.items.len);
        defer gpa.free(map);
        const orphaned_pids = try gpa.alloc(u32, self.exited_by_pid.count());
        defer gpa.free(orphaned_pids);

        // Survivors renumber in place, in order; victims carry the sentinel.
        for (map, 0..) |*to, idx| to.* = @intCast(idx);
        for (victims) |v| map[v] = flows.removed_row;
        var next: u32 = 0;
        for (map) |*to| {
            if (to.* == flows.removed_row) continue;
            to.* = next;
            next += 1;
        }

        // From here on nothing can fail: remapRows takes its own scratch
        // before it touches anything.
        try self.flows.remapRows(gpa, map);

        // Roll the totals up first — still by old index — then compact.
        for (victims) |v| {
            self.rows.items[sink].sent += self.rows.items[v].sent;
            self.rows.items[sink].recv += self.rows.items[v].recv;
        }
        self.compactRows(map, orphaned_pids);
        return true;
    }

    /// Close the ranks behind the evicted rows: drop them from the row list
    /// and renumber every index that named a survivor. Infallible by
    /// construction — the caller has already taken the scratch this needs —
    /// because a half-renumbered table would have Flows pointing at the
    /// wrong process.
    fn compactRows(self: *Core, map: []const u32, orphaned_pids: []u32) void {
        var w: usize = 0;
        for (self.rows.items, 0..) |row, idx| {
            if (map[idx] == flows.removed_row) {
                self.gpa.free(row.name);
                continue;
            }
            self.rows.items[w] = row;
            w += 1;
        }
        self.rows.shrinkRetainingCapacity(w);

        var live_it = self.live_by_pid.iterator();
        while (live_it.next()) |e| {
            // Only exited rows are ever victims, and retiring a row is what
            // takes its PID out of this map — so nothing here can be gone.
            std.debug.assert(map[e.value_ptr.*] != flows.removed_row);
            e.value_ptr.* = map[e.value_ptr.*];
        }
        // The victims' own PID entries have nowhere left to point.
        var orphaned: usize = 0;
        var exited_it = self.exited_by_pid.iterator();
        while (exited_it.next()) |e| {
            const to = map[e.value_ptr.*];
            if (to == flows.removed_row) {
                orphaned_pids[orphaned] = e.key_ptr.*;
                orphaned += 1;
            } else e.value_ptr.* = to;
        }
        for (orphaned_pids[0..orphaned]) |pid| _ = self.exited_by_pid.remove(pid);
    }

    /// The Evicted-processes Row (CONTEXT.md), created on the first
    /// eviction and reused forever after. It owns no PID and no Flows — it
    /// is where attribution stops.
    fn evictedProcessesRow(self: *Core) error{OutOfMemory}!u32 {
        for (self.rows.items, 0..) |r, idx| {
            if (r.evicted_processes) return @intCast(idx);
        }
        const idx: u32 = @intCast(self.rows.items.len);
        const name = try self.gpa.dupe(u8, evicted_processes_name);
        errdefer self.gpa.free(name);
        try self.rows.append(self.gpa, .{
            .pid = 0,
            .create_time = 0,
            .exited = true,
            .evicted_processes = true,
            .name = name,
        });
        return idx;
    }

    /// Cold-start seed and the 10 s reconciliation sweep share this: align
    /// the Flow list with a fresh IP Helper table snapshot.
    pub fn reconcile(
        self: *Core,
        rows: []const tables.SeededConn,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        if (try self.flows.reconcile(self.gpa, rows, self, now_ms, &self.names)) self.dirty = true;
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
    /// row's Flows grouped under it. Speeds are read off the rate rings and
    /// published precomputed — a reader never computes.
    ///
    /// `event_now_ms` is the *event* clock (rates.zig), not the monotonic
    /// `now_ms` the lifecycle calls take: the rings are indexed by the
    /// timestamps ETW stamps events with, and a window has to be read on the
    /// same clock its data was written on.
    pub fn buildSnapshot(
        self: *Core,
        event_now_ms: u64,
    ) error{OutOfMemory}!*snapshot.Snapshot {
        // Flows first, sorted (row, identity, generation): each row's Flows
        // become one contiguous, deterministically ordered span.
        self.flow_scratch.clearRetainingCapacity();
        try self.flows.collect(self.gpa, &self.flow_scratch, event_now_ms);
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
            const speed = row.rate.speed(event_now_ms);
            dst.* = .{
                .pid = row.pid,
                .name = try snapshot.arenaDupe(snap, row.name),
                .exited = row.exited,
                .evicted_processes = row.evicted_processes,
                .sent = row.sent,
                .recv = row.recv,
                .sent_rate = speed.sent,
                .recv_rate = speed.recv,
            };
        }
        // Flows address rows by position — attach spans and count live
        // flows before sorting (the sorted rows carry their slices along).
        // Names are borrowed from the Flow layer, so they are copied into the
        // arena here: a published Snapshot is self-contained.
        for (self.flow_scratch.items, 0..) |e, i| {
            flat[i] = e.flow;
            if (e.flow.remote_hostname) |h|
                flat[i].remote_hostname = try snapshot.arenaDupe(snap, h);
            if (e.flow.remote_alias) |a|
                flat[i].remote_alias = try snapshot.arenaDupe(snap, a);
        }
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

/// Whether the exited-row cap may take this row: exited rows are the only
/// candidates, and the Evicted-processes Row they roll into is not one.
fn cappedRow(row: ProcessRow) bool {
    return row.exited and !row.evicted_processes;
}

/// An event's own timestamp on the rate rings' clock (rates.zig: event-clock
/// milliseconds). A record whose header timestamp is missing or nonsensical
/// buckets at zero, where the ring ages it out on its own.
fn eventMs(ts_ft: i64) u64 {
    if (ts_ft <= 0) return 0;
    return rates.msFromFileTime(@intCast(ts_ft));
}

/// Eviction order for exited rows: smallest In-session Totals first — the
/// least there is to explain — and among equals the oldest, which is the
/// lower index in the append-only row list.
fn leastInformativeFirst(rows: []const ProcessRow, a: u32, b: u32) bool {
    const total_a = rows[a].sent + rows[a].recv;
    const total_b = rows[b].sent + rows[b].recv;
    if (total_a != total_b) return total_a < total_b;
    return a < b;
}

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
        .pid = pid,
        .size = size,
        .local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0)),
        .remote_addr = [4]u8{ 93, 184, 216, 34 } ++ @as([12]u8, @splat(0)),
        .local_port = local_port,
        .remote_port = 443,
        .timestamp_ft = ts,
    };
}

/// Event time as the records carry it: a millisecond reading of the event
/// clock, in the FILETIME 100 ns ticks an ETW header holds.
fn ft(at_ms: u64) i64 {
    return @intCast(at_ms * rates.ft_ticks_per_ms);
}

/// Open `n` distinct byte-less TCP Flows on `pid`, one per local port — the
/// cheapest way to push the Flow table past its cap.
fn floodConnects(core: *Core, pid: u32, first_port: u16, n: u16, now_ms: u64) !void {
    var i: u16 = 0;
    while (i < n) : (i += 1)
        try core.applyEvent(testEvent(.connect, .tcp, pid, 0, first_port + i), now_ms);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try std.testing.expectEqual(@as(u32, 1), rowForPid(snap.rows, 100).?.tcp_conns);

    // Same dedupe for UDP, where the table only knows the local endpoint.
    const udp_data = testEvent(.send, .udp, 300, 10, 5353);
    try core.applyEvent(udp_data, 0);
    try core.reconcile(&.{.{ .pid = 300, .key = event.connKey(udp_data) }}, 0);
    const snap2 = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 700), snap.rows[0].sent);
    try std.testing.expectEqualStrings("\\x\\a.exe", snap.rows[0].name);

    // The PID comes back as a different process: fresh row, fresh totals.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"), 0);
    try core.applyEvent(testEventAt(.send, .tcp, 100, 11, 1, 600), 0);
    const snap2 = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 1), snap.rows.len);
    try std.testing.expect(snap.rows[0].exited);
    try std.testing.expectEqual(@as(u64, 333), snap.rows[0].recv);

    // Even once the PID is reused, an event stamped before the new
    // instance existed still belongs to the exited row.
    try core.applyProcess(procEvent(.start, 100, 500, 0, "\\x\\b.exe"), 0);
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 44, 1, 190), 0);
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 55, 1, 600), 0);
    const snap2 = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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

    const snap = try core.buildSnapshot(0);
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
    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try std.testing.expect(snap.health.rebaselined);
    try std.testing.expectEqual(@as(u64, 3), snap.health.ring_dropped);
    // Totals are marked, never erased.
    try std.testing.expectEqual(@as(u64, 1000), rowForPid(snap.rows, 100).?.sent);

    // Same counters again: no new loss; ETW EventsLost alone triggers.
    try std.testing.expect(!core.noteLoss(3, 0));
    try std.testing.expect(core.noteLoss(3, 5));
    core.flagRebaselined(); // tables unavailable — flag is still mandatory
    const snap2 = try core.buildSnapshot(0);
    defer snap2.release();
    try std.testing.expect(snap2.health.rebaselined); // sticky
    try std.testing.expectEqual(@as(u64, 5), snap2.health.etw_events_lost);
}

test "a TCP connect creates a live Flow under its Process Row" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 0);

    const snap = try core.buildSnapshot(0);
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
    const snap = try core.buildSnapshot(2000);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u32, 0), row.tcp_conns);
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expect(row.flows[0].lingering);
    try std.testing.expectEqual(@as(u64, 999), row.flows[0].sent);

    // One millisecond short of the Linger window: still there.
    try core.tick(11_999);
    const snap2 = try core.buildSnapshot(11999);
    defer snap2.release();
    try std.testing.expectEqual(@as(usize, 1), rowForPid(snap2.rows, 100).?.flows.len);

    // At the boundary it leaves the flow list; the row keeps its bytes.
    try core.tick(12_000);
    const snap3 = try core.buildSnapshot(12000);
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

    const snap = try core.buildSnapshot(2500);
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

    const snap = try core.buildSnapshot(5000);
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

    const snap = try core.buildSnapshot(100);
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

    const snap = try core.buildSnapshot(0);
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
    const snap = try core.buildSnapshot(89999);
    defer snap.release();
    try std.testing.expect(!rowForPid(snap.rows, 300).?.flows[0].lingering);

    // 60 s after the last activity: closed into normal Linger…
    try core.tick(90_000);
    const snap2 = try core.buildSnapshot(90000);
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 300).?;
    try std.testing.expect(row2.flows[0].lingering);
    try std.testing.expectEqual(@as(u32, 0), row2.udp_socks);

    // …and 10 s later it leaves, bytes retained in the row.
    try core.tick(100_000);
    const snap3 = try core.buildSnapshot(100000);
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
    const snap = try core.buildSnapshot(0);
    defer snap.release();
    const seeded_row = rowForPid(snap.rows, 300).?;
    try std.testing.expectEqual(@as(usize, 1), seeded_row.flows.len);
    try std.testing.expectEqual(@as(u16, 0), seeded_row.flows[0].remote_port);

    // Traffic on the socket: the real conversation supersedes the byte-less
    // placeholder outright — one Flow, not a socket shown twice.
    try core.applyEvent(ev, 1000);
    const snap2 = try core.buildSnapshot(1000);
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

    const snap = try core.buildSnapshot(5000);
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
    const snap = try core.buildSnapshot(60000);
    defer snap.release();
    try std.testing.expect(!rowForPid(snap.rows, 300).?.flows[0].lingering);

    // Socket unbound: the next sweep closes the placeholder into Linger.
    try core.reconcile(&.{}, 70_000);
    const snap2 = try core.buildSnapshot(70000);
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

    const snap = try core.buildSnapshot(5000);
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
    const snap2 = try core.buildSnapshot(5000);
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

    const snap = try core.buildSnapshot(1000);
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
    const snap2 = try core.buildSnapshot(11000);
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 0), row2.flows.len);
    try std.testing.expectEqual(@as(u64, 55), row2.sent);
}

// ---------------------------------------------------------------------------
// Hostname Attribution (issue #26) — driven through the same seam: parsed
// records in, published Snapshots out.
// ---------------------------------------------------------------------------

/// The address `testEvent` connects to.
const test_remote: event.IpAddr = .{
    .family = .v4,
    .addr = [4]u8{ 93, 184, 216, 34 } ++ @as([12]u8, @splat(0)),
};
const other_remote: event.IpAddr = .{
    .family = .v4,
    .addr = [4]u8{ 8, 8, 4, 4 } ++ @as([12]u8, @splat(0)),
};

fn dnsEvent(
    pid: u32,
    comptime name: []const u8,
    addrs: []const event.IpAddr,
) event.DnsEvent {
    var ev: event.DnsEvent = .{
        .pid = pid,
        .name_len = name.len,
        .alias_len = 0,
        .addr_count = @intCast(addrs.len),
        .name_buf = undefined,
        .alias_buf = undefined,
        .addrs = undefined,
    };
    @memcpy(ev.name_buf[0..name.len], name);
    @memcpy(ev.addrs[0..addrs.len], addrs);
    return ev;
}

/// A flow event whose remote endpoint is `other_remote` rather than the
/// default one.
fn testEventTo(op: event.Op, pid: u32, local_port: u16, remote: event.IpAddr) event.NetEvent {
    var ev = testEvent(op, .tcp, pid, 0, local_port);
    ev.remote_addr = remote.addr;
    return ev;
}

var test_reverse_name: []const u8 = "";
var test_reverse_calls: u32 = 0;

/// An empty name stands for "this address has no PTR record".
fn testReverseLookup(
    ip: event.IpAddr,
    out: *[event.max_hostname_bytes]u8,
) reverse_lookup.Answer {
    _ = ip;
    test_reverse_calls += 1;
    if (test_reverse_name.len == 0) return .no_record;
    @memcpy(out[0..test_reverse_name.len], test_reverse_name);
    return .{ .named = @intCast(test_reverse_name.len) };
}

/// A lane with its blocking call faked out and its thread never started —
/// tests drive it by hand through `serviceOnce`.
fn attachTestLane(core: *Core, name: []const u8) !*reverse_lookup.Lane {
    const lane = try std.testing.allocator.create(reverse_lookup.Lane);
    lane.* = try reverse_lookup.Lane.init();
    lane.lookup = &testReverseLookup;
    core.reverse = lane;
    test_reverse_name = name;
    test_reverse_calls = 0;
    return lane;
}

fn detachTestLane(lane: *reverse_lookup.Lane) void {
    lane.deinit();
    std.testing.allocator.destroy(lane);
}

fn firstFlow(snap: *snapshot.Snapshot, pid: u32) snapshot.Flow {
    return rowForPid(snap.rows, pid).?.flows[0];
}

fn expectHostname(
    expected: []const u8,
    expected_origin: hostnames.Origin,
    flow: snapshot.Flow,
) !void {
    const name = flow.remote_hostname orelse return error.ExpectedHostname;
    try std.testing.expectEqualStrings(expected, name);
    try std.testing.expectEqual(expected_origin, flow.hostname_origin);
}

test "a Flow opened after a resolution shows the name the process resolved" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    // 3008 fires for cache hits exactly as it does for wire queries
    // (research §3), so at this seam a cache-hit resolution is this record.
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 100);

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try expectHostname("example.com", .observed, firstFlow(snap, 100));
}

test "the CNAME tail rides along to the Flow for optional display" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    var ev = dnsEvent(100, "www.microsoft.test", &.{test_remote});
    const alias = "e13678.dscb.akamaiedge.test";
    @memcpy(ev.alias_buf[0..alias.len], alias);
    ev.alias_len = alias.len;
    try core.applyDns(ev, 0);
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 100);

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    const flow = firstFlow(snap, 100);
    try std.testing.expectEqualStrings("www.microsoft.test", flow.remote_hostname.?);
    try std.testing.expectEqualStrings(alias, flow.remote_alias.?);
}

test "a late observation upgrades and un-dims the Flow in place; the first observed name is permanent" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const lane = try attachTestLane(&core, "ec2-93-184-216-34.compute-1.test");
    defer detachTestLane(lane);

    // Nothing resolved this address yet: the Flow opens showing bare endpoint.
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 0);
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try std.testing.expectEqual(
            @as(?[]const u8, null),
            firstFlow(snap, 100).remote_hostname,
        );
    }

    // The reverse-lookup hint lands — a name, but a dimmed one.
    try core.tick(3_000);
    lane.serviceOnce();
    try core.tick(3_500);
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try expectHostname("ec2-93-184-216-34.compute-1.test", .reverse, firstFlow(snap, 100));
    }

    // The real resolution arrives late and upgrades the live Flow in place.
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 4_000);
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try expectHostname("example.com", .observed, firstFlow(snap, 100));
    }

    // Re-resolution under a different name (CDN churn) must not rewrite a
    // Flow that already carries an observed name: the first one is permanent.
    try core.applyDns(dnsEvent(100, "cdn.elsewhere.test", &.{test_remote}), 5_000);
    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try expectHostname("example.com", .observed, firstFlow(snap, 100));
}

test "a Lingering Flow is upgraded too — it is still on screen" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    const data = testEvent(.send, .tcp, 100, 10, 51000);
    try core.applyEvent(data, 0);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 1_000);
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 2_000);

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    const flow = firstFlow(snap, 100);
    try std.testing.expect(flow.lingering);
    try expectHostname("example.com", .observed, flow);
}

test "an unresolved Flow gets a dimmed reverse name, but not before the grace" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const lane = try attachTestLane(&core, "ptr.example.test");
    defer detachTestLane(lane);

    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 0);

    // Inside the grace nothing is asked — a late 3008 still gets its chance.
    try core.tick(1_000);
    lane.serviceOnce();
    try std.testing.expectEqual(@as(u32, 0), test_reverse_calls);
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try std.testing.expectEqual(
            @as(?[]const u8, null),
            firstFlow(snap, 100).remote_hostname,
        );
    }

    // Past it the lane is asked exactly once, and the answer shows dimmed.
    try core.tick(hostnames.reverse_grace_ms);
    lane.serviceOnce();
    try std.testing.expectEqual(@as(u32, 1), test_reverse_calls);
    try core.tick(hostnames.reverse_grace_ms + 500);
    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try expectHostname("ptr.example.test", .reverse, firstFlow(snap, 100));
}

test "a PTR-less address is asked once, then left alone for the negative window" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const lane = try attachTestLane(&core, ""); // no PTR record
    defer detachTestLane(lane);

    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 0);
    try core.tick(2_000);
    lane.serviceOnce();
    try core.tick(2_500);
    try std.testing.expectEqual(@as(u32, 1), test_reverse_calls);

    // Ticking on for minutes must not re-ask: most cloud ranges have no PTR,
    // and a Flow can outlive the window many times over.
    var now: u64 = 3_000;
    while (now < 2_000 + hostnames.negative_ttl_ms) : (now += 30_000) {
        try core.tick(now);
        lane.serviceOnce();
    }
    try std.testing.expectEqual(@as(u32, 1), test_reverse_calls);

    // The Flow shows its bare endpoint the whole time — nothing is invented.
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try std.testing.expectEqual(
            @as(?[]const u8, null),
            firstFlow(snap, 100).remote_hostname,
        );
    }

    // Once the window passes — measured from when the answer landed — the
    // address is fair game again: networks change.
    try core.tick(2_500 + hostnames.negative_ttl_ms + 1);
    lane.serviceOnce();
    try std.testing.expectEqual(@as(u32, 2), test_reverse_calls);
}

test "a resolver-bypassing process degrades through the tiers, never to a wrong name" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    const lane = try attachTestLane(&core, "ptr.example.test");
    defer detachTestLane(lane);

    // One process resolves normally through the Windows resolver.
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 0);

    // A resolver-bypassing process (nslookup's own stub, in-app DoH) emits no
    // 3008 of its own — the global tier still names its Flow, because some
    // process did observe that address.
    try core.applyEvent(testEvent(.connect, .tcp, 200, 0, 52000), 100);
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try expectHostname("example.com", .observed, firstFlow(snap, 200));
    }

    // For an address nobody resolved, the gap is covered rather than hidden:
    // bare endpoint first, then a dimmed hint — never a borrowed name.
    try core.applyEvent(testEventTo(.connect, 300, 53000, other_remote), 100);
    {
        const snap = try core.buildSnapshot(0);
        defer snap.release();
        try std.testing.expectEqual(
            @as(?[]const u8, null),
            firstFlow(snap, 300).remote_hostname,
        );
    }
    try core.tick(3_000);
    lane.serviceOnce();
    try core.tick(3_500);
    const snap = try core.buildSnapshot(0);
    defer snap.release();
    try expectHostname("ptr.example.test", .reverse, firstFlow(snap, 300));
    // The other process's name never leaked onto it.
    try expectHostname("example.com", .observed, firstFlow(snap, 200));
}

test "a dual-stack Flow matches the v4 observation behind its mapped address" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    // The resolver reports a dual-family lookup's v4 answers as v4.
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 0);

    // The socket is dual-stack, so Kernel-Network reports the same host as a
    // v6 event carrying ::ffff:93.184.216.34. Both sides normalize, or the
    // Flow would silently fall through to a reverse lookup.
    var ev = testEvent(.connect, .tcp, 100, 0, 51000);
    ev.family = .v6;
    ev.remote_addr = [12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++
        [4]u8{ 93, 184, 216, 34 };
    try core.applyEvent(ev, 100);

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    const flow = firstFlow(snap, 100);
    try expectHostname("example.com", .observed, flow);
    // Flow identity is untouched — it really is a v6 conversation.
    try std.testing.expectEqual(event.Family.v6, flow.family);
}

test "a Flow keeps the name it opened with when a new Generation resolves differently" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    try core.applyDns(dnsEvent(100, "first.test", &.{test_remote}), 0);
    const data = testEvent(.send, .tcp, 100, 500, 51000);
    try core.applyEvent(data, 100);
    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 200);

    // The address is re-resolved under a new name, then the endpoints are
    // reused: the new Generation gets the new name, the old keeps its own.
    try core.applyDns(dnsEvent(100, "second.test", &.{test_remote}), 300);
    try core.applyEvent(testEvent(.connect, .tcp, 100, 0, 51000), 400);

    const snap = try core.buildSnapshot(0);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(usize, 2), row.flows.len);
    try expectHostname("first.test", .observed, row.flows[0]);
    try expectHostname("second.test", .observed, row.flows[1]);
}

test "a known-rate transfer surfaces as bytes per second on its Row and its Flow" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // 50 KB/s down: 5 000 B per 100 ms of event time, for 2 s.
    var at: u64 = 0;
    while (at < 2000) : (at += 100)
        try core.applyEvent(testEventAt(.recv, .tcp, 100, 5000, 51000, ft(at)), at);

    const snap = try core.buildSnapshot(2000);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u64, 50_000), row.recv_rate);
    try std.testing.expectEqual(@as(u64, 0), row.sent_rate);
    // Double-bucketed: the Flow carries the same speed as its Row.
    try std.testing.expectEqual(@as(u64, 50_000), row.flows[0].recv_rate);
    // In-session Totals are untouched by the window.
    try std.testing.expectEqual(@as(u64, 100_000), row.recv);
}

test "a flush burst delivering a second of records at once does not spike the rate" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // The same 50 KB/s stream, but every record *arrives* in one drain —
    // what a 120 ms flush tick actually delivers. Bucketing by arrival would
    // pile 100 KB into one bucket and read as a 1 MB/s spike.
    var at: u64 = 0;
    while (at < 2000) : (at += 100)
        try core.applyEvent(testEventAt(.recv, .tcp, 100, 5000, 51000, ft(at)), 2000);

    const snap = try core.buildSnapshot(2000);
    defer snap.release();
    try std.testing.expectEqual(@as(u64, 50_000), rowForPid(snap.rows, 100).?.recv_rate);
}

test "the ring absorbs a late arrival into its own bucket; a later one moves no rate" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    var at: u64 = 0;
    while (at < 2000) : (at += 100)
        try core.applyEvent(testEventAt(.recv, .tcp, 100, 5000, 51000, ft(at)), at);

    // 500 ms late but inside the ring's 1.6 s of history: it belongs to a
    // bucket the 1 s window still covers, so the speed rises by its share.
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 5000, 51000, ft(1500)), 2000);
    const snap = try core.buildSnapshot(2000);
    defer snap.release();
    try std.testing.expectEqual(@as(u64, 55_000), rowForPid(snap.rows, 100).?.recv_rate);

    // Later than the ring can hold: the rate is unmoved — but the bytes are
    // in the totals, where accounting lives.
    try core.applyEvent(testEventAt(.recv, .tcp, 100, 7000, 51000, ft(0)), 2000);
    const snap2 = try core.buildSnapshot(2000);
    defer snap2.release();
    const row = rowForPid(snap2.rows, 100).?;
    try std.testing.expectEqual(@as(u64, 55_000), row.recv_rate);
    try std.testing.expectEqual(@as(u64, 100_000 + 5000 + 7000), row.recv);
}

test "a Snapshot built between flush ticks reads the delivered second, not a starved window" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Tray-idle cadence: a whole second of records lands in one flush, then
    // nothing for a while. A window pinned to *now* would slide off the
    // delivered buckets and read a fraction of the truth; the ring's spare
    // buckets exist so the window can sit back where the data is.
    var at: u64 = 1000;
    while (at < 2000) : (at += 100)
        try core.applyEvent(testEventAt(.recv, .tcp, 100, 5000, 51000, ft(at)), 2000);

    const snap = try core.buildSnapshot(2500);
    defer snap.release();
    try std.testing.expectEqual(@as(u64, 50_000), rowForPid(snap.rows, 100).?.recv_rate);
}

test "speed decays to zero once a Flow goes quiet, totals untouched" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Last bytes at event ms 900.
    var at: u64 = 0;
    while (at < 1000) : (at += 100)
        try core.applyEvent(testEventAt(.send, .tcp, 100, 5000, 51000, ft(at)), at);

    // Still decaying while the lagging window can reach the last bucket.
    const tail = try core.buildSnapshot(2400);
    defer tail.release();
    try std.testing.expect(rowForPid(tail.rows, 100).?.sent_rate > 0);

    // Zero once the ring's whole span — the 1 s window plus the 0.6 s of
    // slack it may sit back into — has passed over the last byte.
    const snap = try core.buildSnapshot(2500);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(@as(u64, 0), row.sent_rate);
    try std.testing.expectEqual(@as(u64, 0), row.flows[0].sent_rate);
    try std.testing.expectEqual(@as(u64, 50_000), row.sent);
}

test "the Flow cap evicts Lingering Flows oldest-first, never a live one" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // 12 000 closed Flows riding out their Linger plus 6 000 live ones:
    // 18 000 against the cap. Everything happens at t=0, so nothing leaves
    // by ordinary Linger expiry — this is the cap talking, not the clock.
    var i: u16 = 0;
    while (i < 12_000) : (i += 1) {
        const ev = testEvent(.send, .tcp, 100, 10, 1000 + i);
        try core.applyEvent(ev, 0);
        var fin = ev;
        fin.op = .disconnect;
        try core.applyEvent(fin, 0);
    }
    try floodConnects(&core, 100, 20_000, 6_000, 0);
    try core.tick(1);

    const snap = try core.buildSnapshot(1);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(flows.cap, row.flows.len);
    // Every live Flow survived; the 1 616 oldest closed ones went.
    try std.testing.expectEqual(@as(u32, 6_000), row.tcp_conns);
    try std.testing.expectEqual(@as(u16, 1000 + 1_616), row.flows[0].local_port);
    try std.testing.expect(row.flows[0].lingering);
    // Eviction coarsens attribution; the bytes are still on the Row.
    try std.testing.expectEqual(@as(u64, 120_000), row.sent);
}

test "live Flows over the cap evict longest-idle first and return as a fresh Generation" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // 17 000 live Flows, each last touched at a distinct moment.
    var i: u16 = 0;
    while (i < 17_000) : (i += 1)
        try core.applyEvent(testEvent(.send, .tcp, 100, 100, 1000 + i), i);
    try core.tick(17_000);

    const snap = try core.buildSnapshot(17_000);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(flows.cap, row.flows.len);
    try std.testing.expectEqual(@as(u16, 1000 + 616), row.flows[0].local_port);
    // The 616 longest-idle Flows left the list; their bytes did not leave
    // the Row (CONTEXT.md "Eviction").
    try std.testing.expectEqual(@as(u64, 1_700_000), row.sent);

    // Activity on an evicted key opens a fresh Generation with its own
    // totals — the old bytes belong to the Row now and never come back.
    try core.applyEvent(testEvent(.send, .tcp, 100, 42, 1000), 17_100);
    const snap2 = try core.buildSnapshot(17_100);
    defer snap2.release();
    const row2 = rowForPid(snap2.rows, 100).?;
    try std.testing.expectEqual(@as(u16, 1000), row2.flows[0].local_port);
    try std.testing.expectEqual(@as(u64, 42), row2.flows[0].sent);
    try std.testing.expectEqual(@as(u64, 1_700_042), row2.sent);
}

test "a Row's speed survives the eviction of the Flows that earned it" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // 50 KB/s on one Flow…
    var at: u64 = 0;
    while (at < 2000) : (at += 100)
        try core.applyEvent(testEventAt(.recv, .tcp, 100, 5000, 51000, ft(at)), at);
    // …then the same process floods the table with byte-less connects. The
    // transfer's Flow is now the longest idle, so the cap takes it first.
    try floodConnects(&core, 100, 1000, 17_000, 2000);
    try core.tick(2000);

    const snap = try core.buildSnapshot(2000);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    for (row.flows) |f| try std.testing.expect(f.local_port != 51000);
    // The Row was bucketed alongside its Flow, so its speed and its totals
    // both outlive it.
    try std.testing.expectEqual(@as(u64, 50_000), row.recv_rate);
    try std.testing.expectEqual(@as(u64, 100_000), row.recv);
}

/// Run `n` short-lived processes, each with one Flow carrying a distinct
/// byte total, and return the bytes they moved between them.
fn runShortLivedProcesses(core: *Core, first_pid: u32, n: u32) !u64 {
    var total: u64 = 0;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const pid = first_pid + i;
        const size = 100 + i;
        try core.applyProcess(procEvent(.start, pid, pid, 0, "\\x\\short.exe"), 0);
        try core.applyEvent(testEvent(.send, .tcp, pid, size, @intCast(5000 + i)), 0);
        try core.applyProcess(procEvent(.stop, pid, pid, 0, ""), 0);
        total += size;
    }
    return total;
}

fn evictedProcessesRow(rows: []const snapshot.Row) ?snapshot.Row {
    for (rows) |r| {
        if (r.evicted_processes) return r;
    }
    return null;
}

fn totalBytes(rows: []const snapshot.Row) u64 {
    var total: u64 = 0;
    for (rows) |r| total += r.sent + r.recv;
    return total;
}

test "the exited-row cap rolls the least informative rows into the Evicted-processes Row" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // 600 short-lived processes against the 512-row cap, plus one live
    // process the cap must never touch.
    const short_lived = try runShortLivedProcesses(&core, 1000, 600);
    try core.applyEvent(testEvent(.send, .tcp, 77, 4242, 40_000), 0);
    try core.tick(1);

    const snap = try core.buildSnapshot(1);
    defer snap.release();

    // The 88 smallest exited rows are gone as rows…
    try std.testing.expectEqual(@as(?snapshot.Row, null), rowForPid(snap.rows, 1000));
    try std.testing.expectEqual(@as(?snapshot.Row, null), rowForPid(snap.rows, 1000 + 87));
    var exited_rows: usize = 0;
    for (snap.rows) |r| {
        if (r.exited and !r.evicted_processes) exited_rows += 1;
    }
    try std.testing.expectEqual(exited_row_cap, exited_rows);

    // …and their bytes are in the one Evicted-processes Row, to the byte.
    const sink = evictedProcessesRow(snap.rows).?;
    try std.testing.expectEqualStrings(evicted_processes_name, sink.name);
    try std.testing.expect(sink.exited);
    try std.testing.expectEqual(@as(usize, 0), sink.flows.len);
    // Sizes 100..187 for the 88 smallest.
    try std.testing.expectEqual(@as(u64, 88 * 100 + 3828), sink.sent);
    // Nothing left the Engine: every byte fed is still on some row.
    try std.testing.expectEqual(short_lived + 4242, totalBytes(snap.rows));

    // A survivor keeps its own Flow — row indices were renumbered, not
    // scrambled.
    const survivor = rowForPid(snap.rows, 1000 + 88).?;
    try std.testing.expectEqual(@as(usize, 1), survivor.flows.len);
    try std.testing.expectEqual(@as(u16, 5088), survivor.flows[0].local_port);
    try std.testing.expect(survivor.flows[0].lingering);

    // The live process is untouched: its row, its totals, its live Flow.
    const live = rowForPid(snap.rows, 77).?;
    try std.testing.expect(!live.exited);
    try std.testing.expectEqual(@as(u64, 4242), live.sent);
    try std.testing.expectEqual(@as(u32, 1), live.tcp_conns);
}

test "a second eviction round reuses the same Evicted-processes Row" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    var fed = try runShortLivedProcesses(&core, 1000, 600);
    try core.tick(1);
    fed += try runShortLivedProcesses(&core, 9000, 200);
    try core.tick(2);

    const snap = try core.buildSnapshot(2);
    defer snap.release();
    var sinks: usize = 0;
    for (snap.rows) |r| {
        if (r.evicted_processes) sinks += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), sinks);
    try std.testing.expectEqual(fed, totalBytes(snap.rows));
}

test "bytes are conserved across arbitrary eviction sequences" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    // Fixed seed: an arbitrary but reproducible mix of traffic, closures,
    // process churn and ticks, run long enough to cross both caps many
    // times over. The invariant under test is the one CONTEXT.md states —
    // eviction may coarsen attribution, never lose bytes — so every byte
    // fed in must still be on some row of every Snapshot.
    var prng = std.Random.DefaultPrng.init(0x2317_5eed);
    const rand = prng.random();

    var pids: [16]u32 = undefined;
    var next_pid: u32 = 1000;
    for (&pids) |*p| {
        p.* = next_pid;
        next_pid += 1;
        try core.applyProcess(procEvent(.start, p.*, p.*, 0, "\\x\\churn.exe"), 0);
    }

    var fed: u64 = 0;
    var now: u64 = 0;
    var round: usize = 0;
    while (round < 40) : (round += 1) {
        var op: usize = 0;
        while (op < 800) : (op += 1) {
            now += rand.uintLessThan(u64, 4);
            const slot = rand.uintLessThan(usize, pids.len);
            const pid = pids[slot];
            const port: u16 = @intCast(1000 + rand.uintLessThan(u32, 20_000));
            switch (rand.uintLessThan(u32, 10)) {
                0 => {
                    // The process exits; a fresh one takes its place.
                    try core.applyProcess(procEvent(.stop, pid, pid, 0, ""), now);
                    pids[slot] = next_pid;
                    next_pid += 1;
                    try core.applyProcess(
                        procEvent(.start, pids[slot], pids[slot], 0, "\\x\\churn.exe"),
                        now,
                    );
                },
                1 => {
                    var fin = testEventAt(.send, .tcp, pid, 0, port, ft(now));
                    fin.op = .disconnect;
                    try core.applyEvent(fin, now);
                },
                else => {
                    const size = 1 + rand.uintLessThan(u32, 4000);
                    const kind: event.Op = if (rand.boolean()) .send else .recv;
                    try core.applyEvent(testEventAt(kind, .tcp, pid, size, port, ft(now)), now);
                    fed += size;
                },
            }
        }
        now += 1 + rand.uintLessThan(u64, 300);
        try core.tick(now);

        const snap = try core.buildSnapshot(now);
        defer snap.release();
        try std.testing.expectEqual(fed, totalBytes(snap.rows));
        try std.testing.expect(snap.flows.len <= flows.cap);
        var exited: usize = 0;
        for (snap.rows) |r| {
            if (r.exited and !r.evicted_processes) exited += 1;
        }
        try std.testing.expect(exited <= exited_row_cap);
    }
    // The churn presses the exited-row cap on its own…
    {
        const churned = try core.buildSnapshot(now);
        defer churned.release();
        try std.testing.expect(evictedProcessesRow(churned.rows).?.sent > 0);
    }
    // …but never reaches 16 k concurrent Flows, so the Flow cap gets its own
    // flood on top of everything the rounds left behind.
    var port: u16 = 0;
    while (port < 20_000) : (port += 1) {
        try core.applyEvent(testEventAt(.recv, .tcp, pids[0], 7, 1000 + port, ft(now)), now);
        fed += 7;
    }
    now += 100;
    try core.tick(now);

    const snap = try core.buildSnapshot(now);
    defer snap.release();
    try std.testing.expectEqual(fed, totalBytes(snap.rows));
    try std.testing.expectEqual(flows.cap, snap.flows.len);
}

// ---------------------------------------------------------------------------
// Where issues #23 and #26 meet: a Flow the memory caps remove is carrying a
// heap-allocated name. Every eviction path has to release it — the caps are
// the only places a Flow leaves the table without closing. The testing
// allocator is the assertion: it fails the test on a leak or a double free.
// ---------------------------------------------------------------------------

test "Flows the cap evicts release their names; the survivors keep theirs" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    // Every testEvent Flow shares one remote address, so a single resolution
    // names all of them — and all 17 000 carry an allocation into the cap.
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 0);
    var i: u16 = 0;
    while (i < 17_000) : (i += 1)
        try core.applyEvent(testEvent(.send, .tcp, 100, 100, 1000 + i), i);
    try core.tick(17_000);

    const snap = try core.buildSnapshot(17_000);
    defer snap.release();
    const row = rowForPid(snap.rows, 100).?;
    try std.testing.expectEqual(flows.cap, row.flows.len);
    // The cap coarsens what is visible, never what is named: what survives
    // still carries the name it opened with.
    try expectHostname("example.com", .observed, row.flows[0]);
    try expectHostname("example.com", .observed, row.flows[row.flows.len - 1]);
}

test "named Lingering Flows the cap takes release their names" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 0);
    // Open and immediately close each Flow, all at the same instant, so the
    // whole Linger queue is still inside its window when the cap arrives —
    // otherwise normal expiry would drain it below the cap and the eviction
    // path under test would never run.
    var i: u16 = 0;
    while (i < 17_000) : (i += 1) {
        const data = testEvent(.send, .tcp, 100, 100, 1000 + i);
        try core.applyEvent(data, 0);
        var fin = data;
        fin.op = .disconnect;
        try core.applyEvent(fin, 0);
    }
    try core.tick(1);

    const snap = try core.buildSnapshot(1);
    defer snap.release();
    try std.testing.expectEqual(flows.cap, snap.flows.len);
    for (snap.flows) |f| try std.testing.expect(f.lingering);
}

test "Flows leaving with an evicted Process Row release their names" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();

    // 600 short-lived processes against the 512-row cap. Their Flows all
    // reach the same address, so every one of them is named before its owning
    // row is evicted out from under it.
    try core.applyDns(dnsEvent(100, "example.com", &.{test_remote}), 0);
    const fed = try runShortLivedProcesses(&core, 1000, 600);
    try core.tick(1);

    const snap = try core.buildSnapshot(1);
    defer snap.release();
    // The Eviction invariant still holds with names in play: attribution
    // coarsened, not one byte moved anywhere but upward.
    try std.testing.expectEqual(fed, totalBytes(snap.rows));
    const survivor = rowForPid(snap.rows, 1000 + 88).?;
    try expectHostname("example.com", .observed, survivor.flows[0]);
}

test "a held Snapshot never changes while the Engine keeps updating" {
    var core = Core.init(std.testing.allocator);
    defer core.deinit();
    var published: snapshot.Published = try .init();
    defer published.deinit();

    try core.applyEvent(testEvent(.send, .tcp, 100, 1000, 51000), 0);
    published.publish(try core.buildSnapshot(0));
    const held = published.acquire().?;
    defer held.release();

    // The Engine moves on: more bytes, a new PID, loss, a new Snapshot.
    try core.applyEvent(testEvent(.send, .tcp, 100, 5000, 51000), 0);
    try core.applyEvent(testEvent(.recv, .tcp, 777, 1, 4000), 0);
    _ = core.noteLoss(9, 0);
    core.flagRebaselined();
    published.publish(try core.buildSnapshot(0));

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
