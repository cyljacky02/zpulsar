//! The Flow layer (issue #22; CONTEXT.md "Flow", "Generation", "Linger"):
//! per-Flow identity, lifecycle, and totals inside the Engine thread's
//! single-threaded state. Flows are keyed (protocol, local endpoint, remote
//! endpoint, owning PID) — for ICMP, (protocol, family, owning PID), see
//! ADR-0003; endpoint reuse after closure starts a new Generation — never
//! resuming the old Flow or its totals. Each Flow binds to its owning Process
//! Row instance (core.zig row index) when it opens and never migrates. Closed
//! Flows Linger 10 s and then leave the list; their bytes live on in the
//! Process Row totals, which are independent accumulators (core.zig), never a
//! sum of visible flows.
//!
//! ICMP (issue #27) is the exception everywhere: it has no byte source and no
//! lifecycle events, its Flows count messages, and inbound messages carry no
//! attribution at all — they are correlated here to the Flow that most
//! recently sent the paired request, or dropped.

const std = @import("std");
const event = @import("event.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

/// Closed Flows stay visible, dimmed, this long (spec issue #18 Data model).
pub const linger_ms: u64 = 10_000;
/// UDP Flows age out after this much inactivity — no lifecycle events exist.
pub const udp_idle_ms: u64 = 60_000;
/// ICMP Flows age out sooner (spec issue #18 Data model): a ping run is over
/// in seconds and nothing else marks its end.
pub const icmp_idle_ms: u64 = 30_000;

/// Flow identity (spec: protocol, local endpoint, remote endpoint, owning
/// PID). Unlike the table-dedupe ConnKey, UDP keeps its real remote endpoint:
/// one socket talking to N remotes is N Flows.
pub const FlowKey = struct {
    tuple: event.ConnKey,
    pid: u32,
};

pub fn flowKey(ev: event.NetEvent) FlowKey {
    // ICMP identity is (protocol, family, owning PID). The spec's original
    // key included the remote address, but under the session's `ut:Global`
    // keyword the send path logs no addresses at all, so an outbound message
    // cannot name its peer — see ADR-0003. The peer is learned from the
    // correlated replies and carried for display only.
    if (ev.proto == .icmp) return icmpKey(ev.family, ev.pid);
    return .{ .pid = ev.pid, .tuple = .{
        .proto = ev.proto,
        .family = ev.family,
        .local_addr = ev.local_addr,
        .remote_addr = ev.remote_addr,
        .local_port = ev.local_port,
        .remote_port = ev.remote_port,
    } };
}

fn icmpKey(family: event.Family, pid: u32) FlowKey {
    return .{ .pid = pid, .tuple = .{
        .proto = .icmp,
        .family = family,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
    } };
}

/// What a Flow accumulated. TCP and UDP move bytes; ICMP has no user-mode
/// byte source, so its Flows count messages and leave `sent`/`recv` at zero
/// — ICMP contributing nothing to any byte total is structural, not a
/// convention downstream code has to remember.
pub const Counts = struct {
    sent: u64 = 0,
    recv: u64 = 0,
    msgs_sent: u64 = 0,
    msgs_recv: u64 = 0,

    fn moved(self: Counts) bool {
        return self.sent + self.recv + self.msgs_sent + self.msgs_recv > 0;
    }
};

const Live = struct {
    generation: u32,
    /// Owning Process Row instance (core.zig row index), bound at open —
    /// a Flow never migrates between Process Rows.
    row: u32,
    counts: Counts = .{},
    /// ICMP only: the peer, learned from the replies this Flow correlated
    /// (ADR-0003) — display, never identity. All-zero until the first reply.
    icmp_remote: [16]u8 = @splat(0),
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
    row: u32,
    counts: Counts,
    icmp_remote: [16]u8,
    expires_at_ms: u64,
};

/// Every request/reply type pair ICMP correlation recognizes — the one table
/// both directions of the lookup read, so a pair can never be half-added.
/// The pairs the spec names are the IPv4 numbering (echo 8→0, timestamp
/// 13→14); ICMPv6 renumbered echo to 128→129 (RFC 4443) and has no timestamp
/// messages, so `ping -6` needs its own row. Everything absent here — errors,
/// neighbor discovery, unsolicited requests — pairs with nothing, which is
/// exactly why unmatched inbound ICMP is dropped.
const reply_pairs = [_]struct { family: event.Family, request: u8, reply: u8 }{
    .{ .family = .v4, .request = 8, .reply = 0 },
    .{ .family = .v4, .request = 13, .reply = 14 },
    .{ .family = .v6, .request = 128, .reply = 129 },
};

/// Which outbound request an inbound ICMP message can be a reply to.
fn pairedRequestType(family: event.Family, reply_type: u8) ?u8 {
    for (reply_pairs) |p| {
        if (p.family == family and p.reply == reply_type) return p.request;
    }
    return null;
}

/// True for the request types `pairedRequestType` can name — the only ones
/// worth remembering a requester for.
fn expectsReply(family: event.Family, request_type: u8) bool {
    for (reply_pairs) |p| {
        if (p.family == family and p.request == request_type) return true;
    }
    return false;
}

/// The correlation index's key. Its value space is bounded by the handful of
/// request types above, so the index cannot grow with traffic and needs no
/// pruning.
const IcmpRequestKey = struct {
    family: event.Family,
    request_type: u8,
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

pub const Table = struct {
    slots: std.AutoHashMapUnmanaged(FlowKey, Slot) = .empty,
    /// Closed Flows in close order — monotonic time makes this expiry order.
    linger: std.ArrayList(Lingering) = .empty,
    linger_head: usize = 0,
    live_count: usize = 0,
    /// Which PID most recently sent an outbound ICMP request of a given
    /// (family, type) — the whole of inbound correlation (ADR-0003).
    /// Overwriting on every request is what "most recent request wins" means.
    icmp_requests: std.AutoHashMapUnmanaged(IcmpRequestKey, u32) = .empty,
    /// Sweep scratch, reused per sweep: the table snapshot's tuples, and the
    /// tuples still-live Flows cover.
    scratch_tuples: std.AutoHashMapUnmanaged(event.ConnKey, void) = .empty,
    scratch_live: std.AutoHashMapUnmanaged(event.ConnKey, void) = .empty,

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        self.slots.deinit(gpa);
        self.linger.deinit(gpa);
        self.icmp_requests.deinit(gpa);
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
                if (l.counts.moved()) _ = try self.close(gpa, key, now_ms);
            }
        }
        _ = try self.touch(gpa, key, row, now_ms);
    }

    /// Remember an outbound ICMP request as the one a matching reply belongs
    /// to. Only request types that have a paired reply are worth recording;
    /// the rest can never be matched anyway.
    pub fn noteIcmpRequest(
        self: *Table,
        gpa: std.mem.Allocator,
        family: event.Family,
        icmp_type: u8,
        pid: u32,
    ) error{OutOfMemory}!void {
        if (!expectsReply(family, icmp_type)) return;
        try self.icmp_requests.put(gpa, .{ .family = family, .request_type = icmp_type }, pid);
    }

    /// The live Flow an inbound ICMP message belongs to: the one whose
    /// process most recently sent the request this message's type pairs with.
    /// Null means unmatched — the caller drops the message outright rather
    /// than inventing activity for a process that asked for nothing
    /// (spec issue #18: "Unmatched inbound ICMP is dropped").
    pub fn matchIcmpReply(
        self: *Table,
        family: event.Family,
        reply_type: u8,
        now_ms: u64,
    ) ?*Live {
        const request_type = pairedRequestType(family, reply_type) orelse return null;
        const pid = self.icmp_requests.get(
            .{ .family = family, .request_type = request_type },
        ) orelse return null;
        // The requester's Flow may have aged out or its process exited since
        // — a reply arriving that late is as unattributable as an unsolicited
        // one.
        const slot = self.slots.getPtr(icmpKey(family, pid)) orelse return null;
        if (slot.live) |*l| {
            l.last_activity_ms = now_ms;
            return l;
        }
        return null;
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
        if (l.counts.moved()) {
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
            .generation = l.generation,
            .row = l.row,
            .counts = l.counts,
            .icmp_remote = l.icmp_remote,
            .expires_at_ms = now_ms + linger_ms,
        });
        slot.live = null;
        slot.linger_count += 1;
        self.live_count -= 1;
        return true;
    }

    /// Time-driven maintenance: retire Lingering Flows whose window ended,
    /// and age idle UDP and ICMP Flows out into normal Linger (no lifecycle
    /// events exist for either). `now_ms` must be monotonic across all Table
    /// calls.
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

        // Inactivity age-out. close() never removes slots, so closing while
        // iterating is safe.
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const idle_limit: u64 = switch (e.key_ptr.tuple.proto) {
                // TCP closure is event-driven, with the table sweep as its
                // safety net — it never ages out on silence.
                .tcp => continue,
                .udp => udp_idle_ms,
                .icmp => icmp_idle_ms,
            };
            const l = e.value_ptr.live orelse continue;
            if (now_ms - l.last_activity_ms >= idle_limit) {
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
                // ICMP is invisible to the owner tables (IP Helper has no
                // ICMP equivalent of GetExtendedTcpTable, research §3), so
                // their silence says nothing: the sweep must neither close
                // an ICMP Flow nor count it as covering a table row. ICMP
                // ages out on inactivity instead.
                .icmp => continue,
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

    /// Every visible Flow — live and Lingering — with its owning row index.
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
                entry(e.key_ptr.*, l.generation, l.row, l.counts, l.icmp_remote, false),
            );
        }
        for (self.linger.items[self.linger_head..]) |l| {
            out.appendAssumeCapacity(
                entry(l.key, l.generation, l.row, l.counts, l.icmp_remote, true),
            );
        }
    }

    fn entry(
        key: FlowKey,
        generation: u32,
        row: u32,
        counts: Counts,
        icmp_remote: [16]u8,
        lingering: bool,
    ) Entry {
        // ICMP keeps its peer outside the key: it is learned from replies, so
        // it is published from the Flow, not from the identity.
        const remote_addr = if (key.tuple.proto == .icmp)
            icmp_remote
        else
            key.tuple.remote_addr;
        return .{ .row = row, .flow = .{
            .proto = key.tuple.proto,
            .family = key.tuple.family,
            .local_addr = key.tuple.local_addr,
            .remote_addr = remote_addr,
            .local_port = key.tuple.local_port,
            .remote_port = key.tuple.remote_port,
            .generation = generation,
            .sent = counts.sent,
            .recv = counts.recv,
            .msgs_sent = counts.msgs_sent,
            .msgs_recv = counts.msgs_recv,
            .lingering = lingering,
        } };
    }
};
