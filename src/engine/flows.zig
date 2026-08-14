//! The Flow layer (issue #22; CONTEXT.md "Flow", "Generation", "Linger"):
//! per-Flow identity, lifecycle, and totals inside the Engine thread's
//! single-threaded state. Flows are keyed (protocol, local endpoint, remote
//! endpoint, owning PID) — for ICMP, (protocol, family, owning PID), see
//! ADR-0003; endpoint reuse after closure starts a new Generation — never
//! resuming the old Flow or its totals. Each Flow binds to its owning Process
//! Row instance (core.zig row index) when it opens and never migrates. Closed
//! Flows Linger 10 s and then leave the list; their bytes live on in the
//! Process Row totals, which are independent accumulators (core.zig), never a
//! sum of visible flows. That independence is what makes the Flow cap (issue
//! #23) safe: this table holds visibility, not accounting, so evicting from
//! it can cost detail but never bytes.
//!
//! ICMP (issue #27) is the exception everywhere: it has no byte source and no
//! lifecycle events, its Flows count messages, and inbound messages carry no
//! attribution at all — they are correlated here to the Flow that most
//! recently sent the paired request, or dropped.

const std = @import("std");
const event = @import("event.zig");
const hostnames = @import("hostnames.zig");
const rates = @import("rates.zig");
const snapshot = @import("snapshot.zig");
const tables = @import("tables.zig");

/// Closed Flows stay visible, dimmed, this long (spec issue #18 Data model).
pub const linger_ms: u64 = 10_000;
/// UDP Flows age out after this much inactivity — no lifecycle events exist.
pub const udp_idle_ms: u64 = 60_000;
/// ICMP Flows age out sooner (spec issue #18 Data model): a ping run is over
/// in seconds and nothing else marks its end.
pub const icmp_idle_ms: u64 = 30_000;
/// The Flow cap (spec issue #18 Data model, "Memory bounds"): at most this
/// many visible Flows. Well past any real machine's connection count, so the
/// cap is a bound on pathology, not a working limit.
pub const cap: usize = 16 * 1024;
/// An owning Process Row that Core evicted, in a `remapRows` table.
pub const removed_row: u32 = std.math.maxInt(u32);

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

/// How far Service Attribution (issue #25) has got with a Flow. The Flow
/// layer only stores this; which tier applies is core.zig's decision.
pub const Resolution = enum {
    /// No service map has covered the owning process instance yet.
    unclassified,
    /// A per-socket owner-module lookup is in flight on the resolver lane.
    pending,
    /// Nothing more will be asked: the answer landed, failed, or was never
    /// needed (the map alone settles single-service and non-service hosts).
    settled,
};

/// A Flow's remote name, resolved once at creation and stored here rather
/// than re-derived per repaint (spec issue #18; research §5). Empty text means
/// the Flow shows its bare endpoint. Strings are owned by the Table.
///
/// An observed name is permanent — the first one wins, so CDN churn cannot
/// rewrite the label a connection was made under. A hint only ever fills a
/// Flow that has no name at all.
const FlowName = struct {
    text: []const u8 = "",
    alias: []const u8 = "",
    origin: hostnames.Origin = .observed,

    fn isObserved(self: FlowName) bool {
        return self.text.len > 0 and self.origin == .observed;
    }

    fn dupe(gpa: std.mem.Allocator, name: hostnames.Name) error{OutOfMemory}!FlowName {
        const text = try gpa.dupe(u8, name.text);
        errdefer gpa.free(text);
        return .{
            .text = text,
            .alias = try gpa.dupe(u8, name.alias),
            .origin = name.origin,
        };
    }

    fn deinit(self: *FlowName, gpa: std.mem.Allocator) void {
        gpa.free(self.text);
        gpa.free(self.alias);
        self.* = .{};
    }
};

pub const Live = struct {
    generation: u32,
    /// Owning Process Row instance (core.zig row index), bound at open —
    /// a Flow never migrates between Process Rows.
    row: u32,
    sent: u64 = 0,
    recv: u64 = 0,
    /// ICMP messages, which is what ICMP moves instead of bytes — no
    /// user-mode source reports its message sizes (ADR-0003). Zero for TCP
    /// and UDP, whose `sent`/`recv` above stay the only byte counters.
    msgs_sent: u64 = 0,
    msgs_recv: u64 = 0,
    /// ICMP only: the peer, learned from the replies this Flow correlated
    /// (ADR-0003) — display, never identity. All-zero until the first reply.
    icmp_remote: [16]u8 = @splat(0),
    /// Event-time byte history behind this Flow's displayed speed. An ICMP
    /// Flow never buckets anything into it: it has no bytes to bucket.
    rate: rates.Ring = .{},
    last_activity_ms: u64,
    /// When the Flow opened — what the reverse-lookup grace is measured from.
    opened_ms: u64,
    name: FlowName = .{},
    resolution: Resolution = .unclassified,
    /// The service that owns this socket, resolved per-socket (tier 2).
    /// Interned by core.zig, so it outlives every service map.
    service: ?[]const u8 = null,
};

/// One key's history: the current live Flow (if any), how many closed
/// generations still Linger, and the last Generation number handed out. The
/// slot leaves the map only when nothing under the key is visible anymore.
const Slot = struct {
    last_gen: u32 = 0,
    live: ?Live = null,
    linger_count: u32 = 0,
};

/// A closed Flow riding out its Linger window: the Flow exactly as it stood
/// at close, frozen. Its rate ring is frozen with it, so the last bytes it
/// moved still show as speed and then decay to zero on their own. Holding
/// the whole `Live` rather than a copy of its fields means a Flow only ever
/// grows a field in one place — the name included, which is why a late
/// observation can still upgrade a Lingering Flow: it is still on screen.
const Lingering = struct {
    key: FlowKey,
    flow: Live,
    expires_at_ms: u64,
};

/// The remote endpoint a Flow's name is keyed on. Normalized, because a
/// dual-stack socket reaching an IPv4 host reports `::ffff:a.b.c.d` while the
/// resolver's answer normalizes to plain v4 — unnormalized, such a Flow could
/// never match its own observation. Flow *identity* keeps the raw address:
/// this is the naming key only.
fn remoteOf(tuple: event.ConnKey) event.IpAddr {
    return (event.IpAddr{ .family = tuple.family, .addr = tuple.remote_addr }).normalized();
}

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

/// Eviction ordering for live Flows: least recently active first.
const Idle = struct {
    key: FlowKey,
    last_activity_ms: u64,
};

fn idleFirst(_: void, a: Idle, b: Idle) bool {
    return a.last_activity_ms < b.last_activity_ms;
}

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
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.live) |*l| l.name.deinit(gpa);
        }
        // Entries before `linger_head` were already released as they retired.
        for (self.linger.items[self.linger_head..]) |*l| l.flow.name.deinit(gpa);
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
    /// after closure). A new Flow resolves its remote name here, once
    /// (CONTEXT.md "Hostname Attribution").
    pub fn touch(
        self: *Table,
        gpa: std.mem.Allocator,
        key: FlowKey,
        row: u32,
        now_ms: u64,
        names: *hostnames.Table,
    ) error{OutOfMemory}!*Live {
        if (self.slots.getPtr(key)) |slot| {
            if (slot.live) |*l| {
                l.last_activity_ms = now_ms;
                return l;
            }
        }
        if (key.tuple.proto == .udp and !isZeroRemote(key.tuple))
            try self.dropUdpPlaceholder(gpa, key, now_ms);
        const name = try resolveName(gpa, key, now_ms, names);
        errdefer {
            var owned = name;
            owned.deinit(gpa);
        }
        const gop = try self.slots.getOrPut(gpa, key);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.last_gen += 1;
        gop.value_ptr.live = .{
            .generation = gop.value_ptr.last_gen,
            .row = row,
            .last_activity_ms = now_ms,
            .opened_ms = now_ms,
            .name = name,
        };
        self.live_count += 1;
        return &gop.value_ptr.live.?;
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
    ///
    /// The returned pointer is into `slots` and is invalidated by anything
    /// that inserts a Flow; use it before the next `touch`.
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

    /// The tiered lookup, done once per Flow. A bound socket with no observed
    /// conversation (the UDP table's zero-remote placeholder) has no remote to
    /// name. An ICMP Flow has no remote in its key either, so it takes this
    /// same path and shows its bare peer — the address is only learned later,
    /// from replies, and by then the name is settled (ADR-0003).
    fn resolveName(
        gpa: std.mem.Allocator,
        key: FlowKey,
        now_ms: u64,
        names: *hostnames.Table,
    ) error{OutOfMemory}!FlowName {
        if (isZeroRemote(key.tuple)) return .{};
        const found = names.lookup(key.pid, remoteOf(key.tuple), now_ms) orelse return .{};
        return FlowName.dupe(gpa, found);
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
        names: *hostnames.Table,
    ) error{OutOfMemory}!*Live {
        if (self.slots.getPtr(key)) |slot| {
            if (slot.live) |l| {
                if (l.sent + l.recv > 0) _ = try self.close(gpa, key, now_ms);
            }
        }
        return self.touch(gpa, key, row, now_ms, names);
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
        if (slot.live == null) return;
        if (slot.live.?.sent + slot.live.?.recv > 0) {
            _ = try self.close(gpa, placeholder, now_ms);
            return;
        }
        slot.live.?.name.deinit(gpa);
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
        // The whole Flow moves across, name included — the live one is
        // dropped in the same breath, so ownership transfers exactly once.
        try self.linger.append(gpa, .{
            .key = key,
            .flow = l,
            .expires_at_ms = now_ms + linger_ms,
        });
        slot.live = null;
        slot.linger_count += 1;
        self.live_count -= 1;
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
            if (self.linger.items[self.linger_head].expires_at_ms > now_ms) break;
            self.retireOldestLingering(gpa);
            changed = true;
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

    /// Enforce the Flow cap (CONTEXT.md "Eviction"). Closed Flows go first,
    /// oldest-first: their bytes already live in their Process Row's totals,
    /// so dropping them costs visibility only. If live Flows alone still
    /// exceed the cap, the longest-idle ones go — the key leaves the table
    /// entirely, so the next activity on it opens a fresh Generation with
    /// its own totals rather than resuming what the Row already holds.
    /// Bytes are never at stake here: no accounting lives in this table.
    /// ICMP message counts are the one thing that lives nowhere else, so an
    /// evicted ICMP Flow does lose them — the cap is a bound on pathology,
    /// and ICMP contributes a handful of Flows to it.
    pub fn evict(self: *Table, gpa: std.mem.Allocator) error{OutOfMemory}!bool {
        if (self.count() <= cap) return false;

        // Closed Flows, in close order.
        while (self.count() > cap and self.linger_head < self.linger.items.len)
            self.retireOldestLingering(gpa);
        self.compactLinger();
        if (self.live_count <= cap) return true;

        // Live Flows, longest idle first. The allocation comes before any
        // live Flow is touched, so an OOM here costs nothing already done —
        // the closed Flows above stay evicted, the next tick retries.
        var idle: std.ArrayList(Idle) = .empty;
        defer idle.deinit(gpa);
        try idle.ensureTotalCapacity(gpa, self.live_count);
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const l = e.value_ptr.live orelse continue;
            idle.appendAssumeCapacity(.{
                .key = e.key_ptr.*,
                .last_activity_ms = l.last_activity_ms,
            });
        }
        std.mem.sort(Idle, idle.items, {}, idleFirst);
        const excess = self.live_count - cap;
        for (idle.items[0..excess]) |victim| {
            const slot = self.slots.getPtr(victim.key).?;
            // The Flow leaves the table outright, so its name goes with it —
            // the next Generation on this key resolves its own.
            slot.live.?.name.deinit(gpa);
            slot.live = null;
            self.live_count -= 1;
            if (slot.linger_count == 0) _ = self.slots.remove(victim.key);
        }
        return true;
    }

    /// Drop the Linger queue's head — whether its window ended or the cap
    /// came for it — and retire the slot behind it if nothing else there is
    /// still visible. Caller must not be iterating `slots`.
    fn retireOldestLingering(self: *Table, gpa: std.mem.Allocator) void {
        const l = self.linger.items[self.linger_head];
        self.linger.items[self.linger_head].flow.name.deinit(gpa);
        self.linger_head += 1;
        const slot = self.slots.getPtr(l.key).?;
        slot.linger_count -= 1;
        if (slot.linger_count == 0 and slot.live == null)
            _ = self.slots.remove(l.key);
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
        names: *hostnames.Table,
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
            _ = try self.touch(gpa, .{ .tuple = r.key, .pid = r.pid }, row, now_ms, names);
            try self.scratch_live.put(gpa, r.key, {});
            changed = true;
        }
        return changed;
    }

    /// Core evicted Process Rows and renumbered the survivors (`map[old]` is
    /// the new index, or `removed_row`): drop every Flow whose owning row is
    /// gone — its bytes went up into the Evicted-processes Row with its
    /// owner — and repoint the rest. Allocation happens before any of it is
    /// applied, so a failure leaves the table untouched.
    pub fn remapRows(
        self: *Table,
        gpa: std.mem.Allocator,
        map: []const u32,
    ) error{OutOfMemory}!void {
        var dead: std.ArrayList(FlowKey) = .empty;
        defer dead.deinit(gpa);
        try dead.ensureTotalCapacity(gpa, self.slots.count());

        // The Linger queue, filtered and compacted to the front. Close order
        // — and so expiry order — is preserved by the in-place walk.
        var w: usize = 0;
        for (self.linger.items[self.linger_head..]) |l| {
            const to = map[l.flow.row];
            if (to == removed_row) {
                // The Flow goes with its owner; its name goes with the Flow.
                var name = l.flow.name;
                name.deinit(gpa);
                continue;
            }
            self.linger.items[w] = l;
            self.linger.items[w].flow.row = to;
            w += 1;
        }
        self.linger.shrinkRetainingCapacity(w);
        self.linger_head = 0;

        // Live Flows, and the per-slot Linger counts the filtered queue now
        // implies.
        var it = self.slots.iterator();
        while (it.next()) |e| {
            e.value_ptr.linger_count = 0;
            if (e.value_ptr.live) |*l| {
                const to = map[l.row];
                if (to == removed_row) {
                    l.name.deinit(gpa);
                    e.value_ptr.live = null;
                    self.live_count -= 1;
                } else l.row = to;
            }
        }
        for (self.linger.items) |l| self.slots.getPtr(l.key).?.linger_count += 1;

        // Slots with nothing visible left leave the map (collected first —
        // removing mid-iteration is not this map's contract).
        var empty = self.slots.iterator();
        while (empty.next()) |e| {
            if (e.value_ptr.live == null and e.value_ptr.linger_count == 0)
                dead.appendAssumeCapacity(e.key_ptr.*);
        }
        for (dead.items) |key| _ = self.slots.remove(key);
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

    /// Apply a per-socket resolution to one Generation. What the module name
    /// denotes is core.zig's call — it holds the service map — so this asks
    /// `ctx.serviceNamed(row, module)` once the owning row is known, then
    /// stores whatever comes back (null = no service could be named).
    ///
    /// The Flow stops asking either way: the answer is as good as it gets,
    /// and a failed lookup leaves the honest fallback standing rather than
    /// retrying against a table row that is already gone. False when the Flow
    /// no longer exists — which is how an answer nobody can see anymore is
    /// dropped.
    pub fn applyOwnerModule(
        self: *Table,
        key: FlowKey,
        generation: u32,
        module: ?[]const u8,
        ctx: anytype,
    ) bool {
        const slot = self.slots.getPtr(key) orelse return false;
        if (slot.live) |*l| {
            if (l.generation == generation) {
                l.service = if (module) |m| ctx.serviceNamed(l.row, m) else null;
                l.resolution = .settled;
                return true;
            }
        }
        // Closed while the lookup was in flight: it still shows for its
        // Linger window, so the label is still worth having.
        if (slot.linger_count == 0) return false;
        for (self.linger.items[self.linger_head..]) |*l| {
            if (l.flow.generation == generation and std.meta.eql(l.key, key)) {
                l.flow.service = if (module) |m| ctx.serviceNamed(l.flow.row, m) else null;
                return true;
            }
        }
        return false;
    }

    /// Hand every live Flow still awaiting its Service Attribution tier
    /// decision to `ctx.classify(key, live)`. Run when a fresh service map
    /// lands: a Flow that opened before any map could describe its process
    /// gets its decision then.
    pub fn eachUnclassified(self: *Table, ctx: anytype) void {
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.live) |*l| {
                if (l.resolution != .unclassified) continue;
                ctx.classify(e.key_ptr.*, l);
            }
        }
    }

    /// A name landed for `ip`: upgrade every visible Flow to that address in
    /// place, live and Lingering alike (spec issue #18: "a later observation
    /// upgrades it in place, and un-dims it"). True if anything changed.
    ///
    /// An observed name is permanent — the first one wins — so this only ever
    /// promotes: bare → hint, bare → observed, hint → observed.
    ///
    /// A bound socket with no observed conversation has no remote to name, so
    /// the zero-remote placeholders sit this out — otherwise a resolver that
    /// answers `0.0.0.0` for blocked names (pi-hole and friends do) would
    /// label every idle UDP socket with whatever it just blocked.
    pub fn applyName(
        self: *Table,
        gpa: std.mem.Allocator,
        ip: event.IpAddr,
        name: hostnames.Name,
    ) error{OutOfMemory}!bool {
        var changed = false;
        var it = self.slots.iterator();
        while (it.next()) |e| {
            if (!namesAddress(e.key_ptr.tuple, ip)) continue;
            if (e.value_ptr.live) |*l|
                changed = try upgrade(gpa, &l.name, name) or changed;
        }
        for (self.linger.items[self.linger_head..]) |*l| {
            if (!namesAddress(l.key.tuple, ip)) continue;
            changed = try upgrade(gpa, &l.flow.name, name) or changed;
        }
        return changed;
    }

    /// Name every Flow still showing a bare endpoint from what the tiers
    /// already hold — one walk of this table, asking the cache per Flow.
    ///
    /// `applyName` above is the shape for a *single* name arriving, and the
    /// startup resolver-cache snapshot (issue #34) is the opposite case:
    /// thousands of names at once, none of them prompted by a Flow. Calling
    /// `applyName` per record would walk this whole table once per record —
    /// the product of two caps, on the Engine thread, at startup, which is
    /// precisely when the latency budget has least room.
    ///
    /// Flows that already carry a name are skipped: an observation is
    /// permanent, and swapping one hint for another is churn the user cannot
    /// act on (see `upgrade`).
    pub fn nameFromTiers(
        self: *Table,
        gpa: std.mem.Allocator,
        names: *hostnames.Table,
        now_ms: u64,
    ) error{OutOfMemory}!bool {
        var changed = false;
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const tuple = e.key_ptr.tuple;
            if (isZeroRemote(tuple)) continue;
            const l = &(e.value_ptr.live orelse continue);
            if (l.name.text.len > 0) continue;
            const found = names.lookup(e.key_ptr.pid, remoteOf(tuple), now_ms) orelse continue;
            changed = try upgrade(gpa, &l.name, found) or changed;
        }
        for (self.linger.items[self.linger_head..]) |*l| {
            if (isZeroRemote(l.key.tuple)) continue;
            if (l.flow.name.text.len > 0) continue;
            const found = names.lookup(l.key.pid, remoteOf(l.key.tuple), now_ms) orelse continue;
            changed = try upgrade(gpa, &l.flow.name, found) or changed;
        }
        return changed;
    }

    /// Whether a name for `ip` belongs on a Flow with this tuple.
    fn namesAddress(tuple: event.ConnKey, ip: event.IpAddr) bool {
        return !isZeroRemote(tuple) and std.meta.eql(remoteOf(tuple), ip);
    }

    fn upgrade(
        gpa: std.mem.Allocator,
        current: *FlowName,
        name: hostnames.Name,
    ) error{OutOfMemory}!bool {
        if (current.isObserved()) return false;
        // A hint fills a blank, never replaces another hint: swapping one
        // guess for another is churn the user cannot act on.
        if (name.origin != .observed and current.text.len > 0) return false;
        const replacement = try FlowName.dupe(gpa, name);
        current.deinit(gpa);
        current.* = replacement;
        return true;
    }

    /// Periodic name maintenance over the live Flows, run at the Engine's
    /// cadence. Two duties, one walk:
    ///
    /// - a Flow that carries a name refreshes its cache entries, so an active
    ///   conversation never idles out of the tiers (research §5);
    /// - a Flow still showing a bare endpoint past the grace becomes a
    ///   reverse-lookup candidate, deduplicated by address.
    ///
    /// Candidates come out claimed (marked in flight): the caller releases the
    /// claim for any address it fails to queue.
    pub fn maintainNames(
        self: *Table,
        gpa: std.mem.Allocator,
        names: *hostnames.Table,
        now_ms: u64,
        reverse_out: *std.ArrayList(event.IpAddr),
    ) error{OutOfMemory}!void {
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const tuple = e.key_ptr.tuple;
            if (isZeroRemote(tuple)) continue;
            const l = e.value_ptr.live orelse continue;
            const ip = remoteOf(tuple);
            if (l.name.text.len > 0) {
                names.touch(e.key_ptr.pid, ip, now_ms);
                continue;
            }
            if (now_ms -| l.opened_ms < hostnames.reverse_grace_ms) continue;
            if (!names.wantsReverse(ip, now_ms)) continue;
            if (!try names.markPending(gpa, ip)) continue;
            reverse_out.append(gpa, ip) catch |err| {
                names.clearPending(ip);
                return err;
            };
        }
    }

    /// Every visible Flow — live and Lingering — with its owning row index,
    /// each carrying the speed its ring reads at `event_now_ms` (the event
    /// clock, rates.zig — not the monotonic clock the lifecycle runs on) and
    /// the name it resolved at creation.
    pub fn collect(
        self: *const Table,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(Entry),
        event_now_ms: u64,
    ) error{OutOfMemory}!void {
        try out.ensureUnusedCapacity(gpa, self.count());
        var it = self.slots.iterator();
        while (it.next()) |e| {
            const l = e.value_ptr.live orelse continue;
            out.appendAssumeCapacity(entry(e.key_ptr.*, l, false, event_now_ms));
        }
        for (self.linger.items[self.linger_head..]) |l| {
            out.appendAssumeCapacity(entry(l.key, l.flow, true, event_now_ms));
        }
    }

    fn entry(key: FlowKey, flow: Live, lingering: bool, event_now_ms: u64) Entry {
        const speed = flow.rate.speed(event_now_ms);
        const name = flow.name;
        // ICMP keeps its peer outside the key: it is learned from replies, so
        // it is published from the Flow, not from the identity.
        const remote_addr = if (key.tuple.proto == .icmp)
            flow.icmp_remote
        else
            key.tuple.remote_addr;
        return .{
            .row = flow.row,
            .flow = .{
                .proto = key.tuple.proto,
                .family = key.tuple.family,
                .local_addr = key.tuple.local_addr,
                .remote_addr = remote_addr,
                .local_port = key.tuple.local_port,
                .remote_port = key.tuple.remote_port,
                .generation = flow.generation,
                .sent = flow.sent,
                .recv = flow.recv,
                .msgs_sent = flow.msgs_sent,
                .msgs_recv = flow.msgs_recv,
                .sent_rate = speed.sent,
                .recv_rate = speed.recv,
                .lingering = lingering,
                // Borrowed from the Table; the Snapshot build copies them into its
                // own arena before publishing.
                .remote_hostname = if (name.text.len > 0) name.text else null,
                .remote_alias = if (name.alias.len > 0) name.alias else null,
                .hostname_origin = name.origin,
                // Interned by core.zig, and copied into the arena alongside
                // the names above.
                .service = flow.service,
            },
        };
    }
};
