//! The startup resolver-cache snapshot (issue #34; spec issue #18 "Capture:
//! hostname observation", "Pre-start names"): one read of the machine's DNS
//! cache at Engine start, feeding hostnames.zig's tier-3 hint seam.
//!
//! ETW has no retroactive events, so a name resolved *before* zPulsar started
//! is invisible to the 3008 lane — the machine's own resolver cache is the
//! only record of it (docs/research/dns-client-etw.md §3). Reading it blocks,
//! which is why this runs once, on the metadata resolver lane (ADR-0002
//! thread 4), and never on the Engine thread.
//!
//! What comes back is a *hint*, not an observation. The cache is per-machine
//! and carries no PID, so it can say "this address was resolved under this
//! name" and nothing about who resolved it — exactly what the hint tier
//! encodes, and why these names render dimmed behind a `[cache]` badge. A
//! probe that fails at any step returns null and the Engine simply keeps the
//! reverse-lookup lane, which is the honest fallback for pre-start names and
//! is what covered them before this existed.
//!
//! **Reading the cache is not free of side effects, whichever route you
//! take.** `DnsGetCacheDataTable` lists the cached (name, type) pairs but
//! carries no data, so the addresses need a `DnsQuery_W` per name — and the
//! DNS-Client provider reports each of those cache hits as a completed
//! resolution, event 3008, in the process that made the call. The documented
//! `MSFT_DNSClientCache` route has the identical problem one step removed: it
//! re-queries every entry inside the WMI provider host, where the echo wears
//! `WmiPrvSE.exe`'s PID and is indistinguishable from a real observation by a
//! process the Engine cannot identify. Here the echo is *ours*, so
//! `core.applyDns` drops it with one PID comparison. That is the whole reason
//! this takes the undocumented export over the documented class, reversing
//! research §3 — see win32.zig and §3 for the measurement.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");
const hostnames = @import("hostnames.zig");

/// One record from the cache, reduced to what naming needs. Not a Row in
/// CONTEXT.md's sense — that word is the Process Row, the unit of display.
pub const CacheRow = struct {
    /// The name the cache was asked about. Constant across a CNAME chain, so
    /// this is the name to show — what 3008's `QueryName` carries.
    entry: []const u8,
    /// The name this particular record belongs to. Equal to `entry` for a
    /// direct answer; the CNAME chain's tail when the answer went through one.
    owner: []const u8,
    /// The address this record carries, or null for the CNAME and other
    /// records that ride along in the same answer.
    addr: ?event.IpAddr,
};

/// One address the cache can name, ready for `hostnames.Table.noteHint`.
/// Slices belong to the Snapshot that owns the Record.
pub const Record = struct {
    ip: event.IpAddr,
    /// The queried name.
    name: []const u8,
    /// The CNAME chain's tail, when the answer went through one; empty
    /// otherwise, exactly like an observation's.
    alias: []const u8 = "",
};

/// The snapshot is bounded by the tier it feeds: past `hostnames.max_entries`
/// distinct addresses the LRU would drop the excess the moment it landed, so
/// there is nothing to gain by carrying it across the lane first.
pub const max_records: u32 = hostnames.max_entries;

/// Which family a DNS record type names an address in, or null for the record
/// types that name something else. The cache is full of those — CNAME chains,
/// the PTR records the reverse-lookup lane leaves behind, SOA — and their data
/// is a *name*, so reading one as an address would be nonsense twice over.
pub fn addressFamily(record_type: u16) ?event.Family {
    return switch (record_type) {
        1 => .v4, // A
        28 => .v6, // AAAA
        else => null,
    };
}

/// The one row shape worth a hint: an address record under a name we asked
/// about. Everything else parses to nothing rather than to a wrong address.
///
/// The returned slices borrow from `row`; the caller copies what it keeps.
pub fn recordFrom(row: CacheRow) ?Record {
    if (row.entry.len == 0) return null;
    const ip = row.addr orelse return null;
    return .{
        // Keyed by the normalized address, or a v4 answer arriving in mapped
        // form could never match the Flow it belongs to.
        .ip = ip.normalized(),
        .name = row.entry,
        // A record answering under its own name went through no CNAME, so
        // there is no tail to show. Matched case-insensitively: DNS names are,
        // and the two need not agree in case.
        .alias = if (std.ascii.eqlIgnoreCase(row.entry, row.owner)) "" else row.owner,
    };
}

/// One resolver-cache snapshot, owned by whoever holds it. Produced on the
/// metadata resolver lane and handed to the Engine thread, which copies the
/// names it keeps into the hint tier and frees this — so it is deliberately
/// self-contained and thread-agnostic, like `service_map.Raw`.
pub const Snapshot = struct {
    records: []Record,
    /// One block backing every record's `name` and `alias`.
    text: []u8,

    pub fn deinit(self: *Snapshot, gpa: std.mem.Allocator) void {
        gpa.free(self.text);
        gpa.free(self.records);
        gpa.destroy(self);
    }
};

/// Copy `records` into a self-contained Snapshot. The single production path
/// and the seam tests drive the Engine through.
///
/// Duplicate addresses collapse to the **first** record: a cache routinely
/// holds several names for one CDN address, a Flow can only show one, and
/// picking deterministically is what keeps the hint tier from disagreeing with
/// Flows that already read it.
///
/// The result is capped at `max_records` *distinct* addresses. The live walk
/// bounds itself too, but on records rather than distinct addresses — that one
/// is a bound on how long the probe may hold the resolver lane, and it is
/// deliberately the looser of the two.
pub fn fromRecords(
    gpa: std.mem.Allocator,
    records: []const Record,
) error{OutOfMemory}!*Snapshot {
    var seen: std.AutoHashMapUnmanaged(event.IpAddr, void) = .empty;
    defer seen.deinit(gpa);
    try seen.ensureTotalCapacity(gpa, @min(records.len, max_records));

    // Names go into a growing block, so their place in it is an offset until
    // the block stops moving — the same shape `service_map.Raw` is built in.
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(gpa);
    var slots: std.ArrayList(Slot) = .empty;
    errdefer slots.deinit(gpa);

    for (records) |src| {
        if (slots.items.len == max_records) break;
        if (seen.contains(src.ip)) continue;
        seen.putAssumeCapacity(src.ip, {});
        try appendRecord(gpa, &text, &slots, src);
    }

    const owned_text = try text.toOwnedSlice(gpa);
    errdefer gpa.free(owned_text);
    const owned = try gpa.alloc(Record, slots.items.len);
    errdefer gpa.free(owned);
    for (slots.items, owned) |s, *dst| dst.* = .{
        .ip = s.ip,
        .name = s.name.of(owned_text),
        .alias = s.alias.of(owned_text),
    };
    slots.deinit(gpa);

    const snap = try gpa.create(Snapshot);
    snap.* = .{ .records = owned, .text = owned_text };
    return snap;
}

/// Copy one record's names into the growing block and note where they landed.
/// Shared by the two places records are gathered — the live walk, and
/// `fromRecords` re-gathering them into a Snapshot.
fn appendRecord(
    gpa: std.mem.Allocator,
    text: *std.ArrayList(u8),
    slots: *std.ArrayList(Slot),
    rec: Record,
) error{OutOfMemory}!void {
    const name_off = text.items.len;
    try text.appendSlice(gpa, rec.name);
    const alias_off = text.items.len;
    try text.appendSlice(gpa, rec.alias);
    try slots.append(gpa, .{
        .ip = rec.ip,
        .name = .{ .off = @intCast(name_off), .len = @intCast(rec.name.len) },
        .alias = .{ .off = @intCast(alias_off), .len = @intCast(rec.alias.len) },
    });
}

/// A record under construction: where its two names sit in the block being
/// grown, recorded as offsets because appending may move it.
const Slot = struct {
    ip: event.IpAddr,
    name: Span,
    alias: Span,

    const Span = struct {
        off: u32,
        len: u32,

        fn of(self: Span, text: []const u8) []const u8 {
            return text[self.off..][0..self.len];
        }
    };
};

// ---------------------------------------------------------------------------
// The live probe. Nothing below is reachable from a unit test — it needs the
// machine's real resolver cache — so the headless rig drives it instead
// (`zpulsar-headless --dns-cache`). Every step degrades the same way: fewer
// records, or null, and the Engine keeps the reverse-lookup lane.
// ---------------------------------------------------------------------------

/// The one-shot probe. Runs on the metadata resolver lane and nowhere else.
///
/// Two stages, because the cache table carries no data: enumerate the cached
/// (name, type) pairs, then ask for the records of each address-typed one.
pub fn query(gpa: std.mem.Allocator) ?*Snapshot {
    var head: ?*win32.DNS_CACHE_ENTRY = null;
    if (win32.DnsGetCacheDataTable(&head) == 0) return null;
    defer freeCacheTable(head);

    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(gpa);
    var slots: std.ArrayList(Slot) = .empty;
    defer slots.deinit(gpa);

    var entry = head;
    while (entry) |e| : (entry = e.next) {
        if (slots.items.len >= max_records) break;
        const family = addressFamily(e.record_type) orelse continue;
        const name_units = std.mem.sliceTo(e.name orelse continue, 0);
        var name_buf: [event.max_hostname_bytes]u8 = undefined;
        const name = utf8From(name_units, &name_buf) orelse continue;
        collectRecords(gpa, e, name, family, &text, &slots) catch return null;
    }

    const records = gpa.alloc(Record, slots.items.len) catch return null;
    defer gpa.free(records);
    for (slots.items, records) |s, *dst| dst.* = .{
        .ip = s.ip,
        .name = s.name.of(text.items),
        .alias = s.alias.of(text.items),
    };
    return fromRecords(gpa, records) catch null;
}

/// Ask the resolver for one cached name's records and keep the addresses.
///
/// The query is a *standard* one: only that reads the machine's cache, and
/// `DNS_QUERY_NO_WIRE_QUERY` — which reads the calling process's own cache and
/// the hosts file — answers nothing at all in a freshly started zPulsar
/// (win32.zig). The consequence is that a name whose entry expires between the
/// table walk and this call goes to the wire. That is a handful of lookups at
/// worst, for names the machine resolved moments ago, and it is the price of
/// there being no read-only path to the cache's data.
fn collectRecords(
    gpa: std.mem.Allocator,
    entry: *win32.DNS_CACHE_ENTRY,
    name: []const u8,
    family: event.Family,
    text: *std.ArrayList(u8),
    slots: *std.ArrayList(Slot),
) error{OutOfMemory}!void {
    var records: ?*win32.DNS_RECORDW = null;
    const rc = win32.DnsQuery_W(
        entry.name,
        @enumFromInt(entry.record_type),
        win32.DNS_QUERY_STANDARD,
        null,
        // The binding types the out-parameter as the ANSI `DNS_RECORDA` even
        // on the wide entry point; the two are the same layout with a
        // differently-typed name pointer, and `DnsQuery_W` writes the wide
        // form. Casting here is what keeps every read below wide.
        @ptrCast(&records),
        null,
    );
    // `DNS_INFO_NO_RECORDS` is the ordinary answer for a negative cache entry
    // — the table lists those too — and needs no special handling.
    if (rc != .NO_ERROR) return;
    defer win32.DnsFree(records, win32.DnsFreeRecordList);

    var record = records;
    while (record) |r| : (record = r.pNext) {
        if (slots.items.len >= max_records) return;
        // An answer to an A query carries its CNAME chain too; only the
        // records of the type asked for name an address.
        if (addressFamily(r.wType) != family) continue;
        // ...and only from the answer section. Measured, `DnsQuery_W` hands
        // back nothing else — 123 records across a live cache, all answers —
        // so this catches nothing today. It is here because the sections it
        // excludes carry address records for *other* names (nameserver glue),
        // and one of those read as the queried name's address would point a
        // name somewhere nobody resolved. Cheap insurance against an edge the
        // measurement did not reach.
        if (win32.dnsRecordSection(r) != win32.DnsSectionAnswer) continue;
        var addr: [16]u8 = @splat(0);
        switch (family) {
            .v4 => @memcpy(addr[0..4], &win32.dnsRecordIp4(r)),
            .v6 => addr = win32.dnsRecordIp6(r),
        }
        var owner_buf: [event.max_hostname_bytes]u8 = undefined;
        const owner = if (r.pName) |p|
            utf8From(std.mem.sliceTo(p, 0), &owner_buf) orelse ""
        else
            "";
        const rec = recordFrom(.{
            .entry = name,
            .owner = owner,
            .addr = .{ .family = family, .addr = addr },
        }) orelse continue;
        try appendRecord(gpa, text, slots, rec);
    }
}

/// The table and every name in it belong to dnsapi.
fn freeCacheTable(head: ?*win32.DNS_CACHE_ENTRY) void {
    var entry = head;
    while (entry) |e| {
        const next = e.next; // read before the entry is gone
        if (e.name) |n| win32.DnsFree(@ptrCast(n), win32.DnsFreeFlat);
        win32.DnsFree(e, win32.DnsFreeFlat);
        entry = next;
    }
}

/// A resolver string as UTF-8 in `out`. Null when it does not fit — and a name
/// longer than the DNS wire limit is not one the Engine could have observed
/// either, so dropping it costs nothing the 3008 lane would have caught.
fn utf8From(units: []const u16, out: *[event.max_hostname_bytes]u8) ?[]const u8 {
    if (units.len == 0 or units.len > out.len) return null;
    // wtf16LeToWtf8 asserts its output fits, so convert into a worst-case
    // buffer first; the bound above is what makes that buffer sufficient.
    var wtf8: [3 * event.max_hostname_bytes]u8 = undefined;
    const n = std.unicode.wtf16LeToWtf8(&wtf8, units);
    if (n == 0 or n > out.len) return null;
    @memcpy(out[0..n], wtf8[0..n]);
    return out[0..n];
}

// ---------------------------------------------------------------------------
// Tests — the pure row filter and the Snapshot's ownership.
// ---------------------------------------------------------------------------

fn v4(bytes: [4]u8) event.IpAddr {
    return .{ .family = .v4, .addr = bytes ++ @as([12]u8, @splat(0)) };
}

fn v6(bytes: [16]u8) event.IpAddr {
    return .{ .family = .v6, .addr = bytes };
}

test "only A and AAAA records name an address" {
    try std.testing.expectEqual(event.Family.v4, addressFamily(1).?);
    try std.testing.expectEqual(event.Family.v6, addressFamily(28).?);
    // The cache is full of these, and every one of them carries a *name* as
    // its data: CNAME chains, the PTR records the reverse lane leaves behind,
    // SOA from negative answers, and the service records in between.
    for ([_]u16{ 0, 2, 5, 6, 12, 15, 16, 33, 65 }) |t| {
        errdefer std.debug.print("type {d} was treated as an address\n", .{t});
        try std.testing.expectEqual(@as(?event.Family, null), addressFamily(t));
    }
}

test "a cached A record names its address under the name that was asked for" {
    const rec = recordFrom(.{
        .entry = "llvm.org",
        .owner = "llvm.org",
        .addr = v4(.{ 54, 67, 122, 174 }),
    }) orelse return error.ExpectedRecord;
    try std.testing.expectEqual(v4(.{ 54, 67, 122, 174 }), rec.ip);
    try std.testing.expectEqualStrings("llvm.org", rec.name);
    // A direct answer went through no CNAME, so there is no tail to show.
    try std.testing.expectEqualStrings("", rec.alias);
}

test "the CNAME chain's tail rides along as the alias" {
    // The live shape: the queried name stays put across the chain while the
    // record's owner moves to the name the address actually belongs to.
    const rec = recordFrom(.{
        .entry = "api.mobbin.com",
        .owner = "37698a2892123b42.vercel-dns-013.com",
        .addr = v4(.{ 64, 239, 109, 193 }),
    }) orelse return error.ExpectedRecord;
    try std.testing.expectEqualStrings("api.mobbin.com", rec.name);
    try std.testing.expectEqualStrings("37698a2892123b42.vercel-dns-013.com", rec.alias);
}

test "an owner differing only in case is the same name, not a CNAME tail" {
    const rec = recordFrom(.{
        .entry = "LLVM.org",
        .owner = "llvm.ORG",
        .addr = v4(.{ 54, 67, 122, 174 }),
    }) orelse return error.ExpectedRecord;
    try std.testing.expectEqualStrings("", rec.alias);
}

test "an IPv4-mapped answer names the v4 address it stands for" {
    const rec = recordFrom(.{
        .entry = "example.com",
        .owner = "example.com",
        .addr = v6([12]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff } ++
            [4]u8{ 104, 20, 23, 154 }),
    }) orelse return error.ExpectedRecord;
    // Or it could never match a Kernel-Network Flow's remote address.
    try std.testing.expectEqual(v4(.{ 104, 20, 23, 154 }), rec.ip);
}

test "a real IPv6 answer stays v6" {
    const addr = v6(.{ 0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x68, 0x10, 0x85, 0xe5 });
    const rec = recordFrom(.{
        .entry = "cloudflare.com",
        .owner = "cloudflare.com",
        .addr = addr,
    }) orelse return error.ExpectedRecord;
    try std.testing.expectEqual(addr, rec.ip);
}

test "a record with no address, or no name asked for, becomes nothing" {
    // The CNAME and PTR rows that ride along in the same answer: real
    // records, no address, and their data is a name.
    try std.testing.expectEqual(@as(?Record, null), recordFrom(.{
        .entry = "api.mobbin.com",
        .owner = "api.mobbin.com",
        .addr = null,
    }));
    try std.testing.expectEqual(@as(?Record, null), recordFrom(.{
        .entry = "",
        .owner = "",
        .addr = v4(.{ 93, 184, 216, 34 }),
    }));
}

test "a Snapshot owns its text independently of the records it was built from" {
    const gpa = std.testing.allocator;
    var entry = [_]u8{ 'l', 'l', 'v', 'm', '.', 'o', 'r', 'g' };
    var tail = [_]u8{ 'c', 'd', 'n', '.', 't', 'e', 's', 't' };
    const snap = try fromRecords(gpa, &.{.{
        .ip = v4(.{ 54, 67, 122, 174 }),
        .name = &entry,
        .alias = &tail,
    }});
    defer snap.deinit(gpa);

    @memset(&entry, 'x'); // the source is gone; the Snapshot's copy is not
    @memset(&tail, 'x');
    try std.testing.expectEqual(@as(usize, 1), snap.records.len);
    try std.testing.expectEqualStrings("llvm.org", snap.records[0].name);
    try std.testing.expectEqualStrings("cdn.test", snap.records[0].alias);
}

test "several names for one CDN address collapse to the first" {
    const gpa = std.testing.allocator;
    const shared = v4(.{ 104, 20, 23, 154 });
    const snap = try fromRecords(gpa, &.{
        .{ .ip = shared, .name = "first.test" },
        .{ .ip = shared, .name = "second.test" },
        .{ .ip = v4(.{ 1, 1, 1, 1 }), .name = "other.test" },
        .{ .ip = shared, .name = "third.test" },
    });
    defer snap.deinit(gpa);

    try std.testing.expectEqual(@as(usize, 2), snap.records.len);
    try std.testing.expectEqualStrings("first.test", snap.records[0].name);
    try std.testing.expectEqualStrings("other.test", snap.records[1].name);
}

test "the snapshot is capped at the hint tier's own bound" {
    const gpa = std.testing.allocator;
    const oversized = try gpa.alloc(Record, max_records + 100);
    defer gpa.free(oversized);
    for (oversized, 0..) |*r, i| {
        var addr: [16]u8 = @splat(0);
        std.mem.writeInt(u32, addr[0..4], @intCast(i), .big);
        r.* = .{ .ip = .{ .family = .v4, .addr = addr }, .name = "filler.test" };
    }

    const snap = try fromRecords(gpa, oversized);
    defer snap.deinit(gpa);
    // Past the cap the LRU would drop them the moment they landed anyway.
    try std.testing.expectEqual(@as(usize, max_records), snap.records.len);
}

test "an empty cache is an empty snapshot, not a failure" {
    const gpa = std.testing.allocator;
    const snap = try fromRecords(gpa, &.{});
    defer snap.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 0), snap.records.len);
}
