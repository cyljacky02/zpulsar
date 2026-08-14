//! The Engine thread's single-threaded state (ADR-0002: one owner, no
//! locks). Rows are process instances keyed (PID, payload CreateTime) —
//! PID reuse yields a fresh row, exited rows persist all session with their
//! In-session Totals intact, and traffic arriving inside the flush window
//! after an exit still lands on the exited row (issue #21). The Flow layer
//! (flows.zig, issue #22) hangs each row's Flows beneath it: Flows bind to
//! their owning row instance at open, close into Linger on disconnect,
//! age-out, sweep, or process exit, and reconcile against IP Helper
//! snapshots. Service Attribution (issue #25) is the tier policy here: rows
//! learn what services they host from SCM maps the resolver lane delivers,
//! Flows are classified the moment they open, and per-socket answers arrive
//! later as completions. Core never blocks on a lookup — it posts requests to
//! an outbox and applies whatever comes back. The unified loss recovery —
//! ring overflow and ETW EventsLost both re-baseline from fresh tables and
//! set the sticky health flag. Totals are honest or marked, never silently
//! low. All lifecycle timing runs on the caller's monotonic `now_ms` so the
//! whole layer is drivable by synthetic clocks.

const std = @import("std");
const device_map = @import("device_map.zig");
const event = @import("event.zig");
const flows = @import("flows.zig");
const resolver = @import("resolver.zig");
const service_map = @import("service_map.zig");
const snapshot = @import("snapshot.zig");
const strings = @import("strings.zig");
const sync = @import("sync.zig");
const tables = @import("tables.zig");

/// What the SCM map says about a process instance. `unknown` is the honest
/// third state: no map has covered this instance yet, so we know neither that
/// it hosts services nor that it doesn't.
const ServiceState = enum { unknown, none, hosted };

/// When the Engine is allowed to re-enumerate the SCM. Refresh is
/// demand-driven rather than polled: a Flow opening on a process no map can
/// describe is the service state change we care about, and Windows offers no
/// cheap notification for the rest. An idle machine starts no processes, so
/// it enumerates nothing at all — which is what keeps this inside the idle
/// CPU budget.
const MapRefresh = struct {
    /// A request is out; a second would enumerate the same SCM twice.
    in_flight: bool = false,
    ever_requested: bool = false,
    last_request_ms: u64 = 0,
    /// When the newest map was installed — the staleness clock.
    installed_ms: u64 = 0,

    /// Floor between enumerations, so a burst of new processes cannot turn
    /// demand-driven refresh into a busy loop.
    const min_interval_ms: u64 = 2_000;
    /// How stale a shared host's hosted-service list may get. A service
    /// stopping inside a host that keeps running produces no process event
    /// and no Flow on an unknown PID, so nothing else would ever notice it.
    const ttl_ms: u64 = 30_000;
    /// How long a request may be outstanding before another is allowed. Both
    /// queues drop work when full, and an answer dropped on the way back
    /// would otherwise leave the map "in flight" — and so never refreshed —
    /// for the rest of the session.
    const request_timeout_ms: u64 = 30_000;

    /// May the Engine ask now? Clears a request whose answer is never coming.
    fn due(self: *MapRefresh, now_ms: u64) bool {
        if (self.in_flight) {
            if (now_ms -| self.last_request_ms < request_timeout_ms) return false;
            self.in_flight = false;
        }
        // The very first request skips the floor: cold start has no map.
        return !self.ever_requested or
            now_ms -| self.last_request_ms >= min_interval_ms;
    }

    fn sent(self: *MapRefresh, now_ms: u64) void {
        self.in_flight = true;
        self.ever_requested = true;
        self.last_request_ms = now_ms;
    }

    /// The map in hand is old enough that a shared host's list may have
    /// drifted from what the SCM now says.
    fn stale(self: *const MapRefresh, now_ms: u64) bool {
        return now_ms -| self.installed_ms >= ttl_ms;
    }
};
/// Ceiling on undrained resolver work. Past it, new Flows keep the honest
/// fallback instead of growing the queue — the label is worth less than the
/// bound.
const outbox_cap: usize = 512;

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
    /// Service Attribution tier 1 (issue #25): the services this instance
    /// hosts, sorted. The slice is owned by Core's gpa; the names are interned
    /// and outlive every map. Set only from a map that was captured after the
    /// instance started, which is what makes it immune to PID reuse — and
    /// frozen at exit, so an exited service host keeps its identity for the
    /// rest of the session even though the SCM has long forgotten it.
    services: []const []const u8 = &.{},
    service_state: ServiceState = .unknown,
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
    /// Service names, interned for the session (issue #25): rows and Flows
    /// reference these, so replacing a service map can never dangle a label.
    names: strings.Pool = .{},
    /// Work for the metadata resolver lane, drained and submitted by the
    /// runner. Core never blocks on a lookup — it only ever asks.
    outbox: std.ArrayList(resolver.Request) = .empty,
    /// When the Engine may next re-enumerate the SCM.
    map_refresh: MapRefresh = .{},

    pub fn init(gpa: std.mem.Allocator) Core {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *Core) void {
        for (self.rows.items) |row| {
            self.gpa.free(row.name);
            self.gpa.free(row.services);
        }
        self.rows.deinit(self.gpa);
        self.live_by_pid.deinit(self.gpa);
        self.exited_by_pid.deinit(self.gpa);
        self.flows.deinit(self.gpa);
        self.drive_map.deinit(self.gpa);
        self.flow_scratch.deinit(self.gpa);
        self.names.deinit(self.gpa);
        self.outbox.deinit(self.gpa);
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
                const row = &self.rows.items[idx];
                if (ev.op == .send)
                    row.sent += ev.size
                else
                    row.recv += ev.size;
                // First activity opens the Flow (raced the table snapshot,
                // or a new Generation after closure).
                const key = flows.flowKey(ev);
                const live = try self.flows.touch(self.gpa, key, idx, now_ms);
                if (ev.op == .send) live.sent += ev.size else live.recv += ev.size;
                if (live.resolution == .unclassified) self.classify(key, live, now_ms);
                self.dirty = true;
            },
            .connect => {
                const idx = try self.rowForTraffic(ev.pid, ev.timestamp_ft);
                const key = flows.flowKey(ev);
                const live = try self.flows.connect(self.gpa, key, idx, now_ms);
                if (live.resolution == .unclassified) self.classify(key, live, now_ms);
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
    }

    /// Set a row's display name from a start/rundown payload, first writer
    /// wins (start and rundown carry the same name).
    fn nameRow(self: *Core, idx: u32, ev: event.ProcessEvent) error{OutOfMemory}!void {
        if (ev.name_len == 0 or self.rows.items[idx].name.len != 0) return;
        var buf: [3 * event.max_image_name_units]u8 = undefined;
        const n = std.unicode.wtf16LeToWtf8(&buf, ev.name());
        self.rows.items[idx].name = try self.drive_map.displayPath(self.gpa, buf[0..n]);
    }

    /// Service Attribution's per-Flow tier decision (issue #25), taken the
    /// moment a Flow opens. Eagerly, because tier 2 needs the socket's
    /// owner-table row to still be there, and a short-lived socket in a shared
    /// host leaves that table fast. Nothing here blocks: the decision is
    /// either free (tiers 1 and 3, from the map already in hand) or a request
    /// posted to the resolver lane.
    fn classify(self: *Core, key: flows.FlowKey, live: *flows.Live, now_ms: u64) void {
        const row = &self.rows.items[live.row];
        switch (row.service_state) {
            // No map covers this instance yet — ask for one and leave the Flow
            // unclassified; the map's arrival takes the decision. A
            // placeholder row is the exception: with no CreateTime there is
            // nothing to key a map against, so no enumeration could settle it
            // and asking for one every time it sends would be pure waste.
            // The Kernel-Process event that names it is what unblocks this.
            .unknown => if (row.create_time != 0) self.requestServiceMap(now_ms),
            // Permanent: the SCM assigns a process its services when it
            // starts, so one that hosts none never begins to. A host gaining
            // or losing a service is the `.hosted` staleness case below.
            .none => live.resolution = .settled,
            .hosted => {
                if (self.map_refresh.stale(now_ms))
                    self.requestServiceMap(now_ms);
                // Tier 1: one service means the row *is* that service, and
                // buildSnapshot names the Flow from it — no lookup at all.
                if (row.services.len < 2) {
                    live.resolution = .settled;
                    return;
                }
                live.resolution = if (self.postRequest(.{ .owner_module = .{
                    .key = key,
                    .generation = live.generation,
                    .create_time = row.create_time,
                } })) .pending else .settled;
            },
        }
    }

    /// Post work to the resolver lane. False when the outbox is full: the
    /// caller must fall back rather than retry.
    fn postRequest(self: *Core, req: resolver.Request) bool {
        if (self.outbox.items.len >= outbox_cap) {
            self.health.service_lookups_dropped += 1;
            return false;
        }
        self.outbox.append(self.gpa, req) catch {
            self.health.service_lookups_dropped += 1;
            return false;
        };
        return true;
    }

    /// Ask for a fresh SCM enumeration, if the refresh policy allows one now.
    /// Also the Engine's startup prime, so the map is warm before the first
    /// Flow needs it.
    pub fn requestServiceMap(self: *Core, now_ms: u64) void {
        if (!self.map_refresh.due(now_ms)) return;
        if (!self.postRequest(.service_map)) return;
        self.map_refresh.sent(now_ms);
    }

    /// Hand queued work to the resolver lane and clear the outbox. Work the
    /// lane cannot take is dropped: the affected Flows keep the honest
    /// fallback rather than the Engine growing a queue behind a busy lane.
    pub fn submitOutbox(self: *Core, lane: *resolver.Lane) void {
        for (self.outbox.items) |req| {
            if (lane.submit(req)) continue;
            self.health.service_lookups_dropped += 1;
            // Same reasoning as the timeout above, immediately: a dropped map
            // request has no answer coming, so stop waiting for one.
            if (req == .service_map) self.map_refresh.in_flight = false;
        }
        self.outbox.clearRetainingCapacity();
    }

    /// Drain everything the resolver lane has finished. Non-blocking by
    /// construction — the Engine thread never waits on a lookup.
    pub fn drainCompletions(self: *Core, lane: *resolver.Lane, now_ms: u64) void {
        while (lane.nextCompletion()) |completion| self.applyCompletion(completion, now_ms);
    }

    /// Apply one finished metadata-resolver lookup (issue #25). Always
    /// consumes the completion's payload — and cannot fail, so no caller ever
    /// has to reason about a half-consumed one.
    pub fn applyCompletion(
        self: *Core,
        completion: resolver.Completion,
        now_ms: u64,
    ) void {
        switch (completion) {
            .service_map => |maybe_raw| {
                self.map_refresh.in_flight = false;
                const raw = maybe_raw orelse return; // query failed: keep what we have
                defer raw.deinit(self.gpa);
                self.installServiceMap(raw);
                self.map_refresh.installed_ms = now_ms;
                // Flows that opened before any map could describe their
                // process get their tier decision now.
                self.flows.eachUnclassified(Classifier{ .core = self, .now_ms = now_ms });
                self.dirty = true;
            },
            .owner_module => |result| {
                defer if (result.module) |m| self.gpa.free(m);
                if (self.flows.applyOwnerModule(
                    result.key,
                    result.generation,
                    result.module,
                    Namer{ .core = self },
                )) self.dirty = true;
            },
        }
    }

    /// The row's hosted service whose name the owner module matches, or null.
    /// The API may answer with the host image ("svchost.exe") or a component
    /// ("timer.dll") instead of a service (research §5 case 3); checking the
    /// answer against what the SCM says the process actually hosts is what
    /// keeps those from being displayed as services. Matching is
    /// case-insensitive, and the SCM's spelling is the one shown.
    fn hostedServiceNamed(self: *Core, row_idx: u32, module: []const u8) ?[]const u8 {
        for (self.rows.items[row_idx].services) |name| {
            if (std.ascii.eqlIgnoreCase(name, module)) return name;
        }
        return null;
    }

    /// `flows.applyOwnerModule` callback: turns a resolved module name into
    /// one of the owning row's hosted services, or nothing.
    const Namer = struct {
        core: *Core,

        pub fn serviceNamed(self: Namer, row: u32, module: []const u8) ?[]const u8 {
            return self.core.hostedServiceNamed(row, module);
        }
    };

    /// `flows.eachUnclassified` callback: re-takes the tier decision at a
    /// fixed instant for every Flow still waiting on one.
    const Classifier = struct {
        core: *Core,
        now_ms: u64,

        pub fn classify(self: Classifier, key: flows.FlowKey, live: *flows.Live) void {
            self.core.classify(key, live, self.now_ms);
        }
    };

    /// Fold a fresh SCM enumeration into the Process Rows. Only instances the
    /// map is entitled to describe are touched: one that started at or after
    /// the capture may be a *different* process wearing a recycled PID
    /// (research §4), and an exited one keeps whatever it had — its services
    /// are history now, not something the SCM still knows.
    fn installServiceMap(self: *Core, raw: *service_map.Raw) void {
        std.mem.sort(service_map.Pair, raw.entries, {}, service_map.pairLessThan);
        for (self.rows.items) |*row| {
            if (row.exited) continue;
            if (row.create_time == 0 or row.create_time >= raw.captured_ft) continue;
            const hosted = service_map.servicesFor(raw.entries, row.pid);
            if (hosted.len == 0) {
                self.gpa.free(row.services);
                row.services = &.{};
                row.service_state = .none;
                continue;
            }
            // Best-effort: a row that cannot be updated keeps its previous
            // (or unknown) state and settles on the next map.
            const list = self.gpa.alloc([]const u8, hosted.len) catch continue;
            for (hosted, list) |src, *dst| {
                dst.* = self.names.intern(self.gpa, src.name) catch {
                    self.gpa.free(list);
                    return;
                };
            }
            self.gpa.free(row.services);
            row.services = list;
            row.service_state = .hosted;
        }
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
        // Connections that predate zPulsar deserve their service too, and at
        // cold start this is what first asks for a map at all.
        self.flows.eachUnclassified(Classifier{ .core = self, .now_ms = now_ms });
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
                .services = try snapshot.arenaDupeStrings(snap, row.services),
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
            // Service Attribution tier 1: a host running exactly one service
            // *is* that service, so every Flow beneath it carries the name
            // with no per-socket call. Shared hosts leave it to tier 2.
            const only_service: ?[]const u8 =
                if (dst.services.len == 1) dst.services[0] else null;
            while (fi < self.flow_scratch.items.len and
                self.flow_scratch.items[fi].row == row_idx) : (fi += 1)
            {
                const f = self.flow_scratch.items[fi].flow;
                // A tier-2 name is interned in Core, so it has to be copied
                // in like the row's names are: a Snapshot outlives nothing it
                // shows. The tier-1 name is already the row's arena copy.
                // A tier-2 name is interned in Core, so it has to be copied
                // in like the row's names are: a Snapshot outlives nothing it
                // shows. The tier-1 name is already the row's arena copy.
                flat[fi].service = if (f.service) |name|
                    try snapshot.arenaDupe(snap, name)
                else
                    only_service;
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

test "a single-service host's Flows attribute to that service by the map alone" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    // The host process exists before the SCM enumeration that describes it.
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(
        gpa,
        200,
        &.{.{ .pid = 900, .name = "Dnscache" }},
    ) }, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 900).?;
    try std.testing.expectEqual(@as(usize, 1), row.services.len);
    try std.testing.expectEqualStrings("Dnscache", row.services[0]);
    // Tier 1: a single-service PID needs no per-socket call at all.
    try std.testing.expectEqualStrings("Dnscache", row.flows[0].service.?);
}

test "a shared host's Flows fall back to the hosted-service list, never a guess" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    // The RPC pair: deliberately grouped by Windows, so this host stays
    // shared even on a split machine (research §1).
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    }) }, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 900).?;
    // The UI composes "svchost.exe (2 services)" from exactly this.
    try std.testing.expectEqual(@as(usize, 2), row.services.len);
    try std.testing.expectEqualStrings("RpcEptMapper", row.services[0]);
    try std.testing.expectEqualStrings("RpcSs", row.services[1]);
    // Two candidates and no per-socket answer yet: naming one would be a
    // guess, so the Flow names none.
    try std.testing.expectEqual(@as(?[]const u8, null), row.flows[0].service);
}

test "a map captured before a process started never describes it" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    // The PID's previous holder hosted Dnscache; this instance started after
    // the enumeration, so the entry may describe a process that is long gone.
    try core.applyProcess(procEvent(.rundown, 900, 300, 0, "\\x\\evil.exe"), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(
        gpa,
        200,
        &.{.{ .pid = 900, .name = "Dnscache" }},
    ) }, 0);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 900).?;
    try std.testing.expectEqual(@as(usize, 0), row.services.len);
    try std.testing.expectEqual(@as(?[]const u8, null), row.flows[0].service);
}

test "an exited service host keeps its services after the SCM forgets it" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    try core.applyEvent(testEvent(.send, .tcp, 900, 40, 51000), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(
        gpa,
        200,
        &.{.{ .pid = 900, .name = "Dnscache" }},
    ) }, 0);
    try core.applyProcess(procEvent(.stop, 900, 100, 400, ""), 1000);

    // A later enumeration no longer lists the PID at all — the exited row is
    // history, and must keep the identity its bytes were attributed under.
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 500, &.{}) }, 2000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 900).?;
    try std.testing.expect(row.exited);
    try std.testing.expectEqual(@as(usize, 1), row.services.len);
    try std.testing.expectEqualStrings("Dnscache", row.services[0]);
    try std.testing.expectEqual(@as(u64, 40), row.sent);
}

/// The one owner-module request the Engine put in its outbox, or null.
fn onlyOwnerRequest(core: *Core) ?resolver.OwnerQuery {
    var found: ?resolver.OwnerQuery = null;
    for (core.outbox.items) |req| switch (req) {
        .owner_module => |q| {
            if (found != null) return null; // more than one: the caller's assert fails
            found = q;
        },
        else => {},
    };
    return found;
}

test "a shared host's Flow shows the fallback at once and upgrades in place" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    }) }, 0);

    const ev = testEvent(.connect, .tcp, 900, 0, 51000);
    try core.applyEvent(ev, 1000);

    // Resolution is asked for the moment the Flow opens — the owner-table row
    // must still exist, and a short-lived socket leaves it fast.
    const query = onlyOwnerRequest(&core).?;
    try std.testing.expectEqual(@as(u32, 900), query.key.pid);
    try std.testing.expectEqual(@as(u16, 51000), query.key.tuple.local_port);
    try std.testing.expectEqual(@as(u32, 1), query.generation);
    try std.testing.expectEqual(@as(u64, 100), query.create_time);

    // Meanwhile the Flow is already visible, under the honest fallback.
    const before = try core.buildSnapshot();
    defer before.release();
    const early = rowForPid(before.rows, 900).?.flows[0];
    try std.testing.expectEqual(@as(?[]const u8, null), early.service);
    try std.testing.expectEqual(@as(u32, 1), early.generation);

    // The lane answers: the same Flow gains its service, in place.
    core.applyCompletion(.{ .owner_module = .{
        .key = query.key,
        .generation = query.generation,
        .module = try gpa.dupe(u8, "RpcSs"),
    } }, 1500);

    const after = try core.buildSnapshot();
    defer after.release();
    const row = rowForPid(after.rows, 900).?;
    try std.testing.expectEqual(@as(usize, 1), row.flows.len);
    try std.testing.expectEqual(@as(u32, 1), row.flows[0].generation);
    try std.testing.expectEqualStrings("RpcSs", row.flows[0].service.?);
    // The host still lists both services — the row is a shared host either way.
    try std.testing.expectEqual(@as(usize, 2), row.services.len);
}

test "a module name that is not one of the hosted services resolves to nothing" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    }) }, 0);
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 1000);
    const query = onlyOwnerRequest(&core).?;

    // The API may return a component or the host image instead of a service
    // (research §5 case 3) — neither names a service, so neither is shown.
    core.applyCompletion(.{ .owner_module = .{
        .key = query.key,
        .generation = query.generation,
        .module = try gpa.dupe(u8, "svchost.exe"),
    } }, 1500);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        rowForPid(snap.rows, 900).?.flows[0].service,
    );
}

test "a resolved service survives the Flow closing into Linger" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    }) }, 0);
    const data = testEvent(.send, .tcp, 900, 99, 51000);
    try core.applyEvent(data, 1000);
    const query = onlyOwnerRequest(&core).?;
    core.applyCompletion(.{ .owner_module = .{
        .key = query.key,
        .generation = query.generation,
        .module = try gpa.dupe(u8, "RpcEptMapper"),
    } }, 1100);

    var fin = data;
    fin.op = .disconnect;
    try core.applyEvent(fin, 2000);

    const snap = try core.buildSnapshot();
    defer snap.release();
    const f = rowForPid(snap.rows, 900).?.flows[0];
    try std.testing.expect(f.lingering);
    try std.testing.expectEqualStrings("RpcEptMapper", f.service.?);
}

test "a Flow that opened before any service map is classified when one lands" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    // A service that had only just started when its first socket appeared:
    // no map covers it yet, so the Engine asks for one and shows the Flow.
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 0);
    try std.testing.expect(core.outbox.items.len == 1);
    try std.testing.expectEqual(resolver.Request.service_map, core.outbox.items[0]);
    try std.testing.expectEqual(@as(?resolver.OwnerQuery, null), onlyOwnerRequest(&core));

    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    }) }, 100);

    // The map's arrival takes the tier decision the Flow was waiting for.
    const query = onlyOwnerRequest(&core).?;
    try std.testing.expectEqual(@as(u16, 51000), query.key.tuple.local_port);
}

test "Flows of processes that host no services ask the lane for nothing" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 700, 100, 0, "\\x\\browser.exe"), 0);
    try core.applyProcess(procEvent(.rundown, 800, 100, 0, "\\x\\svchost.exe"), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(
        gpa,
        200,
        &.{.{ .pid = 800, .name = "Dnscache" }},
    ) }, 0);

    // A plain process, and a host running exactly one service: the map alone
    // settles both, so no per-socket call is ever made.
    try core.applyEvent(testEvent(.connect, .tcp, 700, 0, 51000), 1000);
    try core.applyEvent(testEvent(.connect, .tcp, 800, 0, 51001), 1000);
    try std.testing.expectEqual(@as(?resolver.OwnerQuery, null), onlyOwnerRequest(&core));

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        rowForPid(snap.rows, 700).?.flows[0].service,
    );
    try std.testing.expectEqualStrings(
        "Dnscache",
        rowForPid(snap.rows, 800).?.flows[0].service.?,
    );
}

test "a connection that predates zPulsar gets its service attributed too" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);

    // Cold start: the owner table seeds a shared host's existing connection.
    const ev = testEvent(.connect, .tcp, 900, 0, 51000);
    try core.reconcile(&.{.{ .pid = 900, .key = event.connKey(ev) }}, 0);
    // Nothing yet knows what PID 900 is, so the seed is what asks for a map.
    try std.testing.expectEqual(@as(usize, 1), core.outbox.items.len);
    try std.testing.expectEqual(resolver.Request.service_map, core.outbox.items[0]);

    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "BFE" },
        .{ .pid = 900, .name = "MpsSvc" },
    }) }, 100);
    const query = onlyOwnerRequest(&core).?;
    core.applyCompletion(.{ .owner_module = .{
        .key = query.key,
        .generation = query.generation,
        .module = try gpa.dupe(u8, "MpsSvc"),
    } }, 200);

    const snap = try core.buildSnapshot();
    defer snap.release();
    try std.testing.expectEqualStrings(
        "MpsSvc",
        rowForPid(snap.rows, 900).?.flows[0].service.?,
    );
}

test "the service map is re-enumerated on demand, never in a busy loop" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 700, 100, 0, "\\x\\a.exe"), 0);

    // First Flow on an instance no map describes: ask straight away.
    try core.applyEvent(testEvent(.connect, .tcp, 700, 0, 51000), 0);
    try std.testing.expectEqual(@as(usize, 1), core.outbox.items.len);

    // More Flows while that request is in flight add nothing.
    try core.applyEvent(testEvent(.connect, .tcp, 700, 0, 51001), 10);
    try core.applyEvent(testEvent(.connect, .tcp, 700, 0, 51002), 20);
    try std.testing.expectEqual(@as(usize, 1), core.outbox.items.len);

    // The query fails; a retry still waits out the floor.
    core.applyCompletion(.{ .service_map = null }, 30);
    core.outbox.clearRetainingCapacity();
    try core.applyEvent(testEvent(.connect, .tcp, 700, 0, 51003), 40);
    try std.testing.expectEqual(@as(usize, 0), core.outbox.items.len);
    try core.applyEvent(testEvent(.connect, .tcp, 700, 0, 51004), 2_000);
    try std.testing.expectEqual(@as(usize, 1), core.outbox.items.len);
}

test "a shared host's stale service list is refreshed once it ages out" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    }) }, 1_000);
    core.outbox.clearRetainingCapacity();

    // A service stopping inside a host that keeps running is invisible to us,
    // so a fresh Flow on a list this young asks for no re-enumeration...
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 5_000);
    try std.testing.expectEqual(@as(usize, 1), core.outbox.items.len); // the owner lookup only
    core.outbox.clearRetainingCapacity();

    // ...but once the list is older than its staleness bound, it does.
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51001), 31_000);
    var asked_for_map = false;
    for (core.outbox.items) |req| if (req == .service_map) {
        asked_for_map = true;
    };
    try std.testing.expect(asked_for_map);
}

/// A resolver backend that never answers, for the stall test below.
const StalledLookups = struct {
    entered: sync.WakeEvent,
    stalling: std.atomic.Value(bool) = .init(true),

    fn lookups(self: *StalledLookups) resolver.Lookups {
        return .{ .ctx = self, .queryServiceMap = queryServiceMap, .resolveOwners = resolveOwners };
    }

    fn hold(self: *StalledLookups) void {
        self.entered.set();
        while (self.stalling.load(.acquire)) std.Thread.yield() catch {};
    }

    fn queryServiceMap(ctx: ?*anyopaque, _: std.mem.Allocator) ?*service_map.Raw {
        const self: *StalledLookups = @ptrCast(@alignCast(ctx.?));
        self.hold();
        return null;
    }

    fn resolveOwners(
        ctx: ?*anyopaque,
        _: std.mem.Allocator,
        _: []const resolver.OwnerQuery,
        _: []?[]u8,
    ) void {
        const self: *StalledLookups = @ptrCast(@alignCast(ctx.?));
        self.hold();
    }
};

test "a resolver call that never returns delays no event and no Snapshot" {
    const gpa = std.testing.allocator;
    var core = Core.init(gpa);
    defer core.deinit();
    var stalled: StalledLookups = .{ .entered = try .init() };
    defer stalled.entered.deinit();

    const lane = try gpa.create(resolver.Lane);
    defer gpa.destroy(lane);
    try lane.init(gpa, stalled.lookups());
    defer lane.deinit();
    const thread = try std.Thread.spawn(.{}, resolver.Lane.run, .{lane});

    // Get the lane genuinely wedged inside a lookup first.
    try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
    try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 0);
    core.submitOutbox(lane);
    try std.testing.expectEqual(
        sync.WakeEvent.WaitResult.signaled,
        stalled.entered.timedWait(5_000),
    );

    // Now run the Engine's whole per-pass sequence, many times over, exactly
    // as runner.zig does — while the lane is stuck.
    var last_seq: u64 = 0;
    for (1..201) |i| {
        const now: u64 = @intCast(i * 10);
        core.drainCompletions(lane, now);
        try core.applyEvent(testEventAt(.send, .tcp, 900, 100, 51000, 0), now);
        try core.applyEvent(testEventAt(.recv, .udp, 700, 7, 5353, 0), now);
        try core.tick(now);
        core.submitOutbox(lane);
        const snap = try core.buildSnapshot();
        defer snap.release();
        try std.testing.expect(snap.seq > last_seq);
        last_seq = snap.seq;
    }

    // Every byte landed and every Snapshot was published; the Flows simply
    // never got a service label.
    const snap = try core.buildSnapshot();
    defer snap.release();
    const row = rowForPid(snap.rows, 900).?;
    try std.testing.expectEqual(@as(u64, 200 * 100), row.sent);
    try std.testing.expectEqual(@as(?[]const u8, null), row.flows[0].service);

    stalled.stalling.store(false, .release);
    lane.shutdown();
    thread.join();
}

test "a Snapshot's service labels outlive the Engine that built it" {
    const gpa = std.testing.allocator;
    // Deliberately outlives `core`: a Snapshot is self-contained, so every
    // name it shows must be its own copy, not a borrow of Engine state.
    var snap: *snapshot.Snapshot = undefined;
    {
        var core = Core.init(gpa);
        defer core.deinit();
        try core.applyProcess(procEvent(.rundown, 900, 100, 0, "\\x\\svchost.exe"), 0);
        core.applyCompletion(.{ .service_map = try service_map.fromPairs(gpa, 200, &.{
            .{ .pid = 900, .name = "RpcSs" },
            .{ .pid = 900, .name = "RpcEptMapper" },
        }) }, 0);
        try core.applyEvent(testEvent(.connect, .tcp, 900, 0, 51000), 1000);
        const query = onlyOwnerRequest(&core).?;
        core.applyCompletion(.{ .owner_module = .{
            .key = query.key,
            .generation = query.generation,
            .module = try gpa.dupe(u8, "RpcSs"),
        } }, 1100);
        snap = try core.buildSnapshot();
    }
    defer snap.release();

    // The interner and every row's service list are gone now.
    const row = rowForPid(snap.rows, 900).?;
    try std.testing.expectEqualStrings("RpcSs", row.flows[0].service.?);
    try std.testing.expectEqualStrings("RpcEptMapper", row.services[0]);
    try std.testing.expectEqualStrings("RpcSs", row.services[1]);
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
