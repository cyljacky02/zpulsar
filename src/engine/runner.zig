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
const etw_session = @import("etw_session.zig");
const snapshot = @import("snapshot.zig");
const sync = @import("sync.zig");
const tables = @import("tables.zig");

/// Spec: flush every 100–150 ms while flows are active.
pub const flush_interval_ms: u64 = 120;
/// EventsLost is polled at ~1 s — losses are rare and the query costs a
/// control-path call.
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
    /// research doc §4: consumer handle opens first (events buffer in the
    /// session), then the cold-start table seed, then the threads — events
    /// that raced the seed reconcile by normalized key.
    pub fn start(gpa: std.mem.Allocator, session: etw_session.Session) StartError!*Engine {
        const self = try gpa.create(Engine);
        errdefer gpa.destroy(self);

        const ring = try gpa.create(consumer_mod.Ring);
        errdefer gpa.destroy(ring);
        ring.* = .{};

        const cons = try gpa.create(consumer_mod.Consumer);
        errdefer gpa.destroy(cons);

        var ring_wake = try sync.WakeEvent.init();
        errdefer ring_wake.deinit();
        var published = try snapshot.Published.init();
        errdefer published.deinit();

        cons.* = .init(ring, ring_wake, gpa);
        errdefer cons.deinit();

        self.* = .{
            .gpa = gpa,
            .session = session,
            .ring = ring,
            .consumer = cons,
            .core = .init(gpa),
            .published = published,
            .ring_wake = ring_wake,
        };
        errdefer self.core.deinit();

        try cons.open();
        errdefer cons.close();

        // Cold start: seed pre-existing connections while events pile up in
        // the session's buffers behind the just-opened handle.
        const rows = try tables.snapshotConnections(gpa);
        defer gpa.free(rows);
        try self.core.seed(rows);

        self.consumer_thread = std.Thread.spawn(.{}, consumer_mod.Consumer.run, .{cons}) catch
            return error.SpawnFailed;
        self.engine_thread = std.Thread.spawn(.{}, engineMain, .{self}) catch {
            // The consumer unblocks when the caller stops the session
            // (startup is fail-fast; the process exits right after).
            self.consumer.close();
            return error.SpawnFailed;
        };
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
        var ticks: u32 = 0;

        while (!self.stop_requested.load(.acquire)) {
            while (self.ring.pop()) |ev| {
                self.core.applyEvent(ev) catch {
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
                if (self.core.noteLoss(self.ring.droppedTotal() + self.oom_drops, self.events_lost))
                    self.rebaseline();
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

    /// Unified loss recovery (ADR-0002): re-baseline the connection list
    /// from fresh tables; if even the tables fail, the flag alone still
    /// marks the totals.
    fn rebaseline(self: *Engine) void {
        const rows = tables.snapshotConnections(self.gpa) catch {
            self.core.flagRebaselined();
            return;
        };
        defer self.gpa.free(rows);
        self.core.rebaseline(rows) catch self.core.flagRebaselined();
    }
};
