//! Production wiring of the hot path (issue #20): the consumer thread
//! blocked in ProcessTrace, the Engine thread draining the ring and
//! publishing Snapshots, the 100–150 ms flush tick, and the unified loss
//! recovery. All Engine state lives on the Engine thread (ADR-0002); this
//! file is thread glue around the unit-tested pieces (core, consumer,
//! snapshot) and is exercised live through the headless rig.

const std = @import("std");
const win32 = @import("win32");
const consumer_mod = @import("consumer.zig");
const core_mod = @import("core.zig");
const device_map = @import("device_map.zig");
const etw_session = @import("etw_session.zig");
const snapshot = @import("snapshot.zig");
const sync = @import("sync.zig");
const tables = @import("tables.zig");

/// Spec: flush every 100–150 ms while flows are active.
pub const flush_interval_ms: u64 = 120;
/// Spec issue #18 Data model: the reconciliation sweep against the IP
/// Helper tables — the safety net for lost TCP close events.
pub const sweep_interval_ms: u64 = 10_000;
/// EventsLost is polled at ~1 s — losses are rare and the query costs a
/// control-path call. This is a superset of the sweep's check-loss duty
/// (spec: "the sweep also checks for event loss"), and the loss re-baseline
/// runs the same table reconcile the sweep does.
const loss_check_every_ticks: u32 = 8;
/// Publishing is cheap but allocates an arena; bound it below the flush
/// cadence so a trickle byte still surfaces within the latency budget.
const min_publish_interval_ms: u64 = 50;

pub const StartError = error{
    OutOfMemory,
    EventCreateFailed,
    OpenFailed,
    TableQueryFailed,
    SpawnFailed,
};

pub const Engine = struct {
    gpa: std.mem.Allocator,
    session: etw_session.Session,
    ring: *consumer_mod.Ring,
    process_ring: *consumer_mod.ProcessRing,
    consumer: *consumer_mod.Consumer,
    core: core_mod.Core,
    published: snapshot.Published,
    ring_wake: sync.WakeEvent,
    stop_requested: std.atomic.Value(bool) = .init(false),
    /// Records lost to allocation failure inside the Engine thread; counted
    /// into the ring-loss signal so they trigger the same recovery.
    oom_drops: u64 = 0,
    events_lost: u64 = 0,
    consumer_thread: std.Thread = undefined,
    engine_thread: std.Thread = undefined,

    /// Bring the hot path up on an already-started session. Order per the
    /// research docs: consumer handle opens first (events buffer in the
    /// session), then the cold-start table seed, then the threads, then the
    /// CAPTURE_STATE rundown request — issued only once the consumer is live
    /// so the burst cannot race its startup (kernel-process research §5).
    pub fn start(gpa: std.mem.Allocator, session: etw_session.Session) StartError!*Engine {
        const self = try gpa.create(Engine);
        errdefer gpa.destroy(self);

        const ring = try gpa.create(consumer_mod.Ring);
        errdefer gpa.destroy(ring);
        ring.* = .{};

        const process_ring = try gpa.create(consumer_mod.ProcessRing);
        errdefer gpa.destroy(process_ring);
        process_ring.* = .{};

        const cons = try gpa.create(consumer_mod.Consumer);
        errdefer gpa.destroy(cons);

        var ring_wake = try sync.WakeEvent.init();
        errdefer ring_wake.deinit();
        var published = try snapshot.Published.init();
        errdefer published.deinit();

        cons.* = .init(ring, process_ring, ring_wake, gpa);
        errdefer cons.deinit();

        self.* = .{
            .gpa = gpa,
            .session = session,
            .ring = ring,
            .process_ring = process_ring,
            .consumer = cons,
            .core = .init(gpa),
            .published = published,
            .ring_wake = ring_wake,
        };
        errdefer self.core.deinit();

        // Display-only: a failed drive map just leaves names as raw NT paths.
        self.core.drive_map = device_map.query(gpa) catch .{};

        try cons.open();
        errdefer cons.close();

        // Cold start: seed pre-existing connections while events pile up in
        // the session's buffers behind the just-opened handle.
        const rows = try tables.snapshotConnections(gpa);
        defer gpa.free(rows);
        try self.core.reconcile(rows, 0);

        self.consumer_thread = std.Thread.spawn(.{}, consumer_mod.Consumer.run, .{cons}) catch
            return error.SpawnFailed;
        self.engine_thread = std.Thread.spawn(.{}, engineMain, .{self}) catch {
            // The consumer unblocks when the caller stops the session
            // (startup is fail-fast; the process exits right after).
            self.consumer.close();
            return error.SpawnFailed;
        };

        // Cold-start process rundown: one ID-15 event per live process.
        session.captureState();
        return self;
    }

    /// Full ordered shutdown, session stop included — ControlTrace(STOP) is
    /// never skipped, and it is what deterministically unblocks ProcessTrace.
    pub fn stop(self: *Engine) void {
        self.consumer.close();
        self.session.stop();
        self.consumer_thread.join();
        self.stop_requested.store(true, .release);
        self.ring_wake.set();
        self.engine_thread.join();

        const gpa = self.gpa;
        self.consumer.deinit();
        gpa.destroy(self.consumer);
        gpa.destroy(self.ring);
        gpa.destroy(self.process_ring);
        self.published.deinit();
        self.ring_wake.deinit();
        self.core.deinit();
        gpa.destroy(self);
    }

    /// Reader API (any thread): current Snapshot, caller releases.
    pub fn acquireSnapshot(self: *Engine) ?*snapshot.Snapshot {
        return self.published.acquire();
    }

    /// Reader API: signaled when a new Snapshot is published (auto-reset).
    pub fn snapshotWake(self: *Engine) sync.WakeEvent {
        return self.published.wake;
    }

    fn engineMain(self: *Engine) void {
        const t0 = win32.GetTickCount64();
        var last_flush: u64 = 0;
        var last_publish: u64 = 0;
        var last_sweep: u64 = 0;
        var ticks: u32 = 0;

        while (!self.stop_requested.load(.acquire)) {
            const drain_now = win32.GetTickCount64() - t0;
            // Identity first: a start/rundown drained before its instance's
            // traffic saves the placeholder round trip.
            while (self.process_ring.pop()) |pev| {
                self.core.applyProcess(pev, drain_now) catch {
                    self.oom_drops += 1;
                };
            }
            while (self.ring.pop()) |ev| {
                self.core.applyEvent(ev, drain_now) catch {
                    self.oom_drops += 1;
                };
            }

            const now = win32.GetTickCount64() - t0;
            if (now - last_flush >= flush_interval_ms) {
                last_flush = now;
                self.session.flush();
                ticks +%= 1;
                if (ticks % loss_check_every_ticks == 0) {
                    if (self.session.queryEventsLost()) |lost| self.events_lost = lost;
                }
                const ring_loss = self.ring.droppedTotal() + self.process_ring.droppedTotal() +
                    self.oom_drops;
                if (self.core.noteLoss(ring_loss, self.events_lost))
                    self.rebaseline(now);
                // Flow lifecycle rides the flush tick: Linger expiry and UDP
                // age-out. OOM leaves the table unchanged; the next tick
                // retries.
                self.core.tick(now) catch {};
                if (now - last_sweep >= sweep_interval_ms) {
                    last_sweep = now;
                    self.sweep(now);
                }
            }

            if (self.core.dirty and now - last_publish >= min_publish_interval_ms) {
                if (self.core.buildSnapshot()) |snap| {
                    self.published.publish(snap);
                    last_publish = now;
                } else |_| {} // OOM: retry next pass
            }

            const now2 = win32.GetTickCount64() - t0;
            var wait_ms = flush_interval_ms -| (now2 -| last_flush);
            // Unpublished state must not sleep through the flush interval —
            // wake as soon as the publish throttle reopens, or the trickle
            // path busts the 200 ms budget.
            if (self.core.dirty)
                wait_ms = @min(wait_ms, min_publish_interval_ms -| (now2 -| last_publish));
            if (wait_ms > 0 and self.ring.isEmpty())
                _ = self.ring_wake.timedWait(@intCast(wait_ms));
        }
    }

    /// The 10 s reconciliation sweep: close Flows whose close events were
    /// lost, keep seeded sockets honest. A failed round is skipped — the
    /// next sweep retries.
    fn sweep(self: *Engine, now_ms: u64) void {
        const rows = tables.snapshotConnections(self.gpa) catch return;
        defer self.gpa.free(rows);
        self.core.reconcile(rows, now_ms) catch {};
    }

    /// Unified loss recovery (ADR-0002): re-baseline the Flow list from
    /// fresh tables and re-request the process rundown (missed starts/stops
    /// re-materialize as ID-15 events, deduped on the row key); if even the
    /// tables fail, the flag alone still marks the totals.
    fn rebaseline(self: *Engine, now_ms: u64) void {
        self.session.captureState();
        const rows = tables.snapshotConnections(self.gpa) catch {
            self.core.flagRebaselined();
            return;
        };
        defer self.gpa.free(rows);
        self.core.rebaseline(rows, now_ms) catch self.core.flagRebaselined();
    }
};
