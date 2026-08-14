//! The Hostname Attribution observation cache (issue #26; CONTEXT.md
//! "Hostname Attribution"): the tiered address→name lookup a Flow consults
//! once, at creation.
//!
//! Three tiers, in precedence order (spec issue #18; research §5):
//!
//!   1. **exact** `(PID, address)` — the name *this* process actually
//!      resolved. Authoritative, and the only tier that separates two
//!      processes reaching the same CDN address under different names.
//!   2. **global** `address` — any process's observation, last writer wins.
//!      Covers a Flow whose own process never queried (a helper resolved for
//!      it, or the socket was handed over).
//!   3. **hints** `address` — the startup resolver-cache snapshot
//!      (dns_cache.zig, issue #34) and reverse-lookup results. Not "the name
//!      the process resolved", so they render dimmed; Microsoft's own guidance
//!      is that reverse lookups are "inherently unreliable, and should be used
//!      only as a hint" (§7). Both fill the tier through `noteHint`, and
//!      neither can displace an observation — they live in their own tier.
//!
//! A miss shows the bare endpoint. Alongside the tiers this owns the two
//! pieces of state that keep the reverse-lookup lane honest: the negative
//! cache (PTR-less addresses are not re-queried for ~10 minutes) and the
//! in-flight set (one query per address, not one per Flow).
//!
//! 3008 carries no TTL, so resolver TTLs are deliberately not mirrored (§5):
//! every tier is a bounded LRU that expires on idle age, refreshed both on
//! upsert and on the activity of a Flow already attributed to it. An entry
//! lost to either bound costs a name until the next observation — never a
//! wrong one. A process's exact-tier entries also die with the process, so a
//! reused PID inherits nothing.

const std = @import("std");
const event = @import("event.zig");

/// Which tier produced a displayed name. Only `observed` is "the name the
/// process actually resolved"; the other two are hints and render dimmed with
/// their own marker (spec issue #18 UI; research §7).
pub const Origin = enum(u8) { observed, cache, reverse };

/// A name as the tiers hold it. Slices belong to the Table and are valid only
/// until its next mutation — callers copy what they keep.
pub const Name = struct {
    text: []const u8,
    /// The CNAME chain's tail: the name the address actually belongs to, for
    /// optional display. Empty for answers that went through no CNAME — and
    /// always for reverse-lookup hints, which are one PTR record and have no
    /// chain to report. Cache hints do carry one: the resolver cache records
    /// the chain the same way a 3008 answer does.
    alias: []const u8 = "",
    origin: Origin,
};

/// Spec issue #18: the observation cache is LRU-capped (~8 k entries). The cap
/// is per tier, not shared: the tiers hold different things and must not
/// starve each other, and at ~100 bytes per entry the worst case across all
/// three is a couple of MB against a 30 MB Tray-idle budget.
pub const max_entries: u32 = 8192;
/// The negative cache only suppresses queries, so it is bounded well below
/// the name tiers: overflowing it costs a repeated lookup, not a wrong name.
pub const max_negative: u32 = 4096;
/// Research §5: entries untouched this long are expired. An active Flow keeps
/// its own attribution alive, so this only reaps addresses nothing talks to.
///
/// Deliberately not called *eviction*: CONTEXT.md reserves that term for
/// rolling an item's totals upward under a memory cap, which never loses
/// bytes. Dropping a name loses only a label, and it comes back on the next
/// observation.
pub const idle_expiry_ms: u64 = 30 * 60 * 1000;
/// Research §7: an address with no PTR record is not re-queried this soon.
pub const negative_ttl_ms: u64 = 10 * 60 * 1000;
/// Spec issue #18: the reverse-lookup lane fires this long after a Flow opens
/// having missed every tier — the grace that lets a late 3008 land first.
pub const reverse_grace_ms: u64 = 2000;

/// Tier 1's key: the same address resolved by two processes is two entries.
pub const PidIp = struct {
    pid: u32,
    ip: event.IpAddr,
};

/// The in-flight reverse-lookup set is bounded like everything else; at the
/// bound the lane simply is not asked, and the Flow shows its bare endpoint.
pub const max_pending: u32 = 256;

pub const Table = struct {
    /// Tier 1 — `(PID, address)`.
    exact: Store(PidIp, max_entries) = .{},
    /// Tier 2 — `address`, last writer wins.
    global: Store(event.IpAddr, max_entries) = .{},
    /// Tier 3 — cache-snapshot and reverse-lookup hints.
    hints: Store(event.IpAddr, max_entries) = .{},
    /// Addresses with no PTR record. The names are empty: only the entry's
    /// age matters, and it is never refreshed on read, or it would never
    /// expire.
    negative: Store(event.IpAddr, max_negative) = .{},
    /// Addresses with a reverse lookup in flight.
    pending: std.AutoHashMapUnmanaged(event.IpAddr, void) = .empty,

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        self.exact.deinit(gpa);
        self.global.deinit(gpa);
        self.hints.deinit(gpa);
        self.negative.deinit(gpa);
        self.pending.deinit(gpa);
    }

    /// A completed resolution (event 3008): upsert tiers 1 and 2.
    pub fn observe(
        self: *Table,
        gpa: std.mem.Allocator,
        pid: u32,
        ip: event.IpAddr,
        name: Name,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        try self.exact.put(gpa, .{ .pid = pid, .ip = ip }, name, now_ms);
        try self.global.put(gpa, ip, name, now_ms);
        self.negative.remove(gpa, ip);
    }

    /// A tier-3 hint: a reverse-lookup result, or an entry from the startup
    /// resolver-cache snapshot. Never overwrites an observation — it lives in
    /// its own tier — and clears any negative entry for the address.
    pub fn noteHint(
        self: *Table,
        gpa: std.mem.Allocator,
        ip: event.IpAddr,
        name: Name,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        try self.hints.put(gpa, ip, name, now_ms);
        self.negative.remove(gpa, ip);
    }

    /// A process exited: drop the names it alone observed, so a reused PID
    /// cannot inherit them (research §5). The global tier keeps them — the
    /// address really was resolved under that name, just not by whoever holds
    /// the PID now.
    pub fn forgetPid(self: *Table, gpa: std.mem.Allocator, pid: u32) void {
        self.exact.removePid(gpa, pid);
    }

    /// The address has no PTR record: suppress re-query for the negative TTL.
    pub fn noteMissing(
        self: *Table,
        gpa: std.mem.Allocator,
        ip: event.IpAddr,
        now_ms: u64,
    ) error{OutOfMemory}!void {
        // Only the entry's age matters here; the name is deliberately empty.
        try self.negative.put(gpa, ip, .{ .text = "", .origin = .reverse }, now_ms);
    }

    /// The tiered lookup a Flow does once, at creation.
    ///
    /// Every tier holding the address is refreshed, not just the winning one:
    /// a name in use keeps its whole chain alive, and the tiers then age in
    /// step instead of drifting apart and expiring different addresses.
    pub fn lookup(self: *Table, pid: u32, ip: event.IpAddr, now_ms: u64) ?Name {
        const exact = self.exact.get(.{ .pid = pid, .ip = ip }, now_ms);
        const global = self.global.get(ip, now_ms);
        const hint = self.hints.get(ip, now_ms);
        return exact orelse global orelse hint;
    }

    /// Keep an already-attributed Flow's entries alive (research §5: "an
    /// active flow keeps its attribution alive regardless of DNS TTL").
    pub fn touch(self: *Table, pid: u32, ip: event.IpAddr, now_ms: u64) void {
        _ = self.lookup(pid, ip, now_ms);
    }

    /// Should the reverse-lookup lane be asked about this address? False when
    /// any tier already names it, when it is known PTR-less, and when a query
    /// for it is already in flight.
    pub fn wantsReverse(self: *Table, ip: event.IpAddr, now_ms: u64) bool {
        // Asking must not count as use, or a stream of unnamed Flows would
        // keep the very entries it is asking about from ever expiring.
        if (self.global.contains(ip) or self.hints.contains(ip)) return false;
        if (self.pending.contains(ip)) return false;
        if (self.negative.lastSeen(ip)) |seen| {
            if (now_ms -| seen < negative_ttl_ms) return false;
        }
        return true;
    }

    /// Claim the address for one in-flight reverse lookup. False when the
    /// in-flight set is full — the caller simply does not query.
    pub fn markPending(
        self: *Table,
        gpa: std.mem.Allocator,
        ip: event.IpAddr,
    ) error{OutOfMemory}!bool {
        if (self.pending.count() >= max_pending) return false;
        try self.pending.put(gpa, ip, {});
        return true;
    }

    pub fn clearPending(self: *Table, ip: event.IpAddr) void {
        _ = self.pending.remove(ip);
    }

    /// Idle expiry across every tier, plus negative-entry expiry. Cheap: each
    /// store is LRU-ordered, so this walks only what it actually retires.
    pub fn sweep(self: *Table, gpa: std.mem.Allocator, now_ms: u64) void {
        self.exact.expireIdle(gpa, now_ms, idle_expiry_ms);
        self.global.expireIdle(gpa, now_ms, idle_expiry_ms);
        self.hints.expireIdle(gpa, now_ms, idle_expiry_ms);
        self.negative.expireIdle(gpa, now_ms, negative_ttl_ms);
    }
};

/// A bounded LRU map from `Key` to an owned name, shared by all four tiers.
/// Recency is an intrusive doubly-linked list over a slot pool, so the cap
/// evicts and the idle sweep reaps in O(1) per entry — the sweep never walks
/// entries it is going to keep.
fn Store(comptime Key: type, comptime capacity: u32) type {
    return struct {
        const Self = @This();
        /// End-of-list / empty sentinel; a real index can never reach it.
        const none = std.math.maxInt(u32);

        const Slot = struct {
            key: Key,
            text: []u8,
            alias: []u8,
            origin: Origin,
            last_seen_ms: u64,
            prev: u32,
            next: u32,
            /// False for slots sitting on the free list. Those hold no
            /// allocation, so teardown must skip them rather than hand the
            /// allocator memory it never gave out.
            in_use: bool,
        };

        slots: std.ArrayList(Slot) = .empty,
        index: std.AutoHashMapUnmanaged(Key, u32) = .empty,
        /// Most and least recently used.
        head: u32 = none,
        tail: u32 = none,
        /// Recycled slots, chained through `next`.
        free: u32 = none,

        fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            for (self.slots.items) |slot| {
                if (slot.in_use) releaseText(gpa, slot);
            }
            self.slots.deinit(gpa);
            self.index.deinit(gpa);
        }

        fn put(
            self: *Self,
            gpa: std.mem.Allocator,
            key: Key,
            name: Name,
            now_ms: u64,
        ) error{OutOfMemory}!void {
            if (self.index.get(key)) |idx| {
                const text = try gpa.dupe(u8, name.text);
                errdefer gpa.free(text);
                const alias = try gpa.dupe(u8, name.alias);
                const slot = &self.slots.items[idx];
                releaseText(gpa, slot.*);
                slot.text = text;
                slot.alias = alias;
                slot.origin = name.origin;
                slot.last_seen_ms = now_ms;
                self.moveToFront(idx);
                return;
            }
            // Reserve the index slot and make room *before* allocating the
            // name, so a failure never leaves a half-inserted entry.
            try self.index.ensureUnusedCapacity(gpa, 1);
            if (self.index.count() >= capacity) self.expireLeastRecent(gpa);
            const text = try gpa.dupe(u8, name.text);
            errdefer gpa.free(text);
            const alias = try gpa.dupe(u8, name.alias);
            errdefer gpa.free(alias);
            const idx = try self.acquireSlot(gpa);
            self.slots.items[idx] = .{
                .key = key,
                .text = text,
                .alias = alias,
                .origin = name.origin,
                .last_seen_ms = now_ms,
                .prev = none,
                .next = none,
                .in_use = true,
            };
            self.index.putAssumeCapacity(key, idx);
            self.pushFront(idx);
        }

        /// Read and refresh: the entry becomes the most recently used.
        fn get(self: *Self, key: Key, now_ms: u64) ?Name {
            const idx = self.index.get(key) orelse return null;
            const slot = &self.slots.items[idx];
            slot.last_seen_ms = now_ms;
            self.moveToFront(idx);
            return .{ .text = slot.text, .alias = slot.alias, .origin = slot.origin };
        }

        /// Presence without refreshing — asking about an entry is not using
        /// it, so this must never touch recency.
        fn contains(self: *Self, key: Key) bool {
            return self.index.contains(key);
        }

        /// Likewise read-only: when the entry was last written or used.
        fn lastSeen(self: *Self, key: Key) ?u64 {
            const idx = self.index.get(key) orelse return null;
            return self.slots.items[idx].last_seen_ms;
        }

        fn remove(self: *Self, gpa: std.mem.Allocator, key: Key) void {
            const idx = self.index.fetchRemove(key) orelse return;
            self.recycle(gpa, idx.value);
        }

        /// Drop every entry belonging to `pid`. Only instantiated for the
        /// per-process tier, whose key carries one.
        fn removePid(self: *Self, gpa: std.mem.Allocator, pid: u32) void {
            for (self.slots.items, 0..) |slot, i| {
                if (!slot.in_use or slot.key.pid != pid) continue;
                _ = self.index.remove(slot.key);
                self.recycle(gpa, @intCast(i));
            }
        }

        fn expireIdle(self: *Self, gpa: std.mem.Allocator, now_ms: u64, idle_ms: u64) void {
            while (self.tail != none) {
                if (now_ms -| self.slots.items[self.tail].last_seen_ms < idle_ms) return;
                self.expireLeastRecent(gpa);
            }
        }

        fn expireLeastRecent(self: *Self, gpa: std.mem.Allocator) void {
            const idx = self.tail;
            if (idx == none) return;
            _ = self.index.remove(self.slots.items[idx].key);
            self.recycle(gpa, idx);
        }

        /// Unlink, free the name, and return the slot to the free list. The
        /// caller has already dropped the index entry.
        fn recycle(self: *Self, gpa: std.mem.Allocator, idx: u32) void {
            self.unlink(idx);
            const slot = &self.slots.items[idx];
            releaseText(gpa, slot.*);
            slot.text = "";
            slot.alias = "";
            slot.in_use = false;
            slot.next = self.free;
            self.free = idx;
        }

        fn acquireSlot(self: *Self, gpa: std.mem.Allocator) error{OutOfMemory}!u32 {
            if (self.free != none) {
                const idx = self.free;
                self.free = self.slots.items[idx].next;
                return idx;
            }
            const idx: u32 = @intCast(self.slots.items.len);
            try self.slots.append(gpa, undefined);
            return idx;
        }

        fn moveToFront(self: *Self, idx: u32) void {
            if (self.head == idx) return;
            self.unlink(idx);
            self.pushFront(idx);
        }

        fn pushFront(self: *Self, idx: u32) void {
            const slot = &self.slots.items[idx];
            slot.prev = none;
            slot.next = self.head;
            if (self.head != none) self.slots.items[self.head].prev = idx;
            self.head = idx;
            if (self.tail == none) self.tail = idx;
        }

        fn unlink(self: *Self, idx: u32) void {
            const slot = self.slots.items[idx];
            if (slot.prev != none)
                self.slots.items[slot.prev].next = slot.next
            else if (self.head == idx) self.head = slot.next;
            if (slot.next != none)
                self.slots.items[slot.next].prev = slot.prev
            else if (self.tail == idx) self.tail = slot.prev;
        }

        fn releaseText(gpa: std.mem.Allocator, slot: Slot) void {
            gpa.free(slot.text);
            gpa.free(slot.alias);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests — the tiers as a Flow sees them: what `lookup` returns, and whether
// the reverse lane gets asked.
// ---------------------------------------------------------------------------

fn ip4(comptime bytes: [4]u8) event.IpAddr {
    return .{ .family = .v4, .addr = bytes ++ @as([12]u8, @splat(0)) };
}

const addr_a = ip4(.{ 93, 184, 216, 34 });
const addr_b = ip4(.{ 104, 20, 23, 154 });

fn observed(text: []const u8) Name {
    return .{ .text = text, .origin = .observed };
}

fn expectName(expected: []const u8, expected_origin: Origin, actual: ?Name) !void {
    const name = actual orelse return error.ExpectedName;
    try std.testing.expectEqualStrings(expected, name.text);
    try std.testing.expectEqual(expected_origin, name.origin);
}

test "the exact tier gives each process the name it resolved itself" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    // The CDN reality: one address, two processes, two names.
    try table.observe(gpa, 100, addr_a, observed("api.example.com"), 0);
    try table.observe(gpa, 200, addr_a, observed("cdn.other.test"), 0);

    try expectName("api.example.com", .observed, table.lookup(100, addr_a, 0));
    try expectName("cdn.other.test", .observed, table.lookup(200, addr_a, 0));
}

test "the global tier names a Flow whose own process never resolved" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try table.observe(gpa, 100, addr_a, observed("api.example.com"), 0);
    // A different process connects to the same address: still an observed
    // name, just not one this process asked for. Last writer wins.
    try expectName("api.example.com", .observed, table.lookup(999, addr_a, 0));
    try table.observe(gpa, 200, addr_a, observed("cdn.other.test"), 10);
    try expectName("cdn.other.test", .observed, table.lookup(999, addr_a, 10));
}

test "hints never outrank an observation" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try table.noteHint(gpa, addr_a, .{ .text = "ec2-93-184-216-34.compute-1.test", .origin = .reverse }, 0);
    try expectName("ec2-93-184-216-34.compute-1.test", .reverse, table.lookup(100, addr_a, 0));

    // The real thing lands: the observation takes over, in every tier order.
    try table.observe(gpa, 100, addr_a, observed("api.example.com"), 100);
    try expectName("api.example.com", .observed, table.lookup(100, addr_a, 100));
    try expectName("api.example.com", .observed, table.lookup(999, addr_a, 100));
}

test "a cache-derived hint is marked as such, not passed off as observed" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    try table.noteHint(std.testing.allocator, addr_a, .{ .text = "pre-start.example.com", .origin = .cache }, 0);
    try expectName("pre-start.example.com", .cache, table.lookup(100, addr_a, 0));
}

test "the CNAME tail rides along with the observation" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    try table.observe(std.testing.allocator, 100, addr_a, .{
        .text = "www.microsoft.com",
        .alias = "e13678.dscb.akamaiedge.net",
        .origin = .observed,
    }, 0);
    const name = table.lookup(100, addr_a, 0) orelse return error.ExpectedName;
    try std.testing.expectEqualStrings("e13678.dscb.akamaiedge.net", name.alias);
}

test "a process's own observations die with it, so a reused PID cannot inherit them" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try table.observe(gpa, 100, addr_a, observed("api.example.com"), 0);
    try table.observe(gpa, 100, addr_b, observed("cdn.example.com"), 0);
    try table.observe(gpa, 200, addr_a, observed("other.example.com"), 0);

    table.forgetPid(gpa, 100);

    // Whoever holds PID 100 next starts clean in the exact tier...
    try std.testing.expectEqual(@as(?Name, null), table.exact.get(.{ .pid = 100, .ip = addr_a }, 0));
    try std.testing.expectEqual(@as(?Name, null), table.exact.get(.{ .pid = 100, .ip = addr_b }, 0));
    // ...another process's entries are untouched...
    try expectName("other.example.com", .observed, table.exact.get(.{ .pid = 200, .ip = addr_a }, 0));
    // ...and the global tier keeps the name: that address really was resolved
    // under it, just not by whoever holds the PID now.
    try expectName("cdn.example.com", .observed, table.lookup(100, addr_b, 0));
}

test "an unknown address wants a reverse lookup; a named one never does" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try std.testing.expect(table.wantsReverse(addr_a, 0));
    try table.observe(gpa, 100, addr_a, observed("api.example.com"), 0);
    try std.testing.expect(!table.wantsReverse(addr_a, 0));
    // A hint counts too — a dimmed name is still a name.
    try std.testing.expect(table.wantsReverse(addr_b, 0));
    try table.noteHint(gpa, addr_b, .{ .text = "ptr.test", .origin = .reverse }, 0);
    try std.testing.expect(!table.wantsReverse(addr_b, 0));
}

test "a PTR-less address is not re-queried inside the negative window" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try table.noteMissing(gpa, addr_a, 1_000);
    try std.testing.expect(!table.wantsReverse(addr_a, 1_000));
    try std.testing.expect(!table.wantsReverse(addr_a, 1_000 + negative_ttl_ms - 1));
    // Past the window the address is fair game again — networks change.
    try std.testing.expect(table.wantsReverse(addr_a, 1_000 + negative_ttl_ms));
}

test "one reverse lookup per address, not one per Flow" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try std.testing.expect(try table.markPending(gpa, addr_a));
    // A second Flow to the same address must not queue a duplicate query.
    try std.testing.expect(!table.wantsReverse(addr_a, 0));
    table.clearPending(addr_a);
    try std.testing.expect(table.wantsReverse(addr_a, 0));
}

test "a reverse result clears the address's negative entry" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try table.noteMissing(gpa, addr_a, 0);
    try table.noteHint(gpa, addr_a, .{ .text = "ptr.test", .origin = .reverse }, 10);
    // The name wins outright, and nothing lingers to suppress a future query.
    try expectName("ptr.test", .reverse, table.lookup(100, addr_a, 10));
}

test "the LRU cap bounds the cache and drops the least recently used name" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    var i: u32 = 0;
    while (i < max_entries) : (i += 1) {
        try table.observe(gpa, 100, addrFor(i), observed("filler.test"), 0);
    }
    // Use the oldest entry, then overflow the cap by one.
    try expectName("filler.test", .observed, table.lookup(100, addrFor(0), 1));
    try table.observe(gpa, 100, addrFor(max_entries), observed("newest.test"), 2);

    // The newest is in and the oldest survived because it was just used; the
    // second-oldest — untouched since insert — is what went.
    try expectName("newest.test", .observed, table.lookup(100, addrFor(max_entries), 2));
    try expectName("filler.test", .observed, table.lookup(100, addrFor(0), 2));
    try std.testing.expectEqual(@as(?Name, null), table.lookup(100, addrFor(1), 2));
}

test "idle entries are evicted; ones a Flow still uses survive" {
    var table: Table = .{};
    defer table.deinit(std.testing.allocator);
    const gpa = std.testing.allocator;

    try table.observe(gpa, 100, addr_a, observed("busy.test"), 0);
    try table.observe(gpa, 100, addr_b, observed("idle.test"), 0);

    // An attributed Flow's activity keeps its entry alive (research §5).
    const late = idle_expiry_ms + 1_000;
    table.touch(100, addr_a, late - 1);
    table.sweep(gpa, late);

    try expectName("busy.test", .observed, table.lookup(100, addr_a, late));
    try std.testing.expectEqual(@as(?Name, null), table.lookup(100, addr_b, late));
}

/// Distinct addresses for the cap tests, spread across all four octets.
fn addrFor(i: u32) event.IpAddr {
    var addr: [16]u8 = @splat(0);
    std.mem.writeInt(u32, addr[0..4], i, .big);
    return .{ .family = .v4, .addr = addr };
}
