//! Tier 2 of Service Attribution (issue #25;
//! docs/research/svchost-service-attribution.md §2): resolving one socket to
//! the service that created it, for the shared hosts tier 1 cannot split.
//!
//! The extended TCP/UDP tables have an OWNER_MODULE shape whose rows carry
//! per-socket ownership recorded by the stack at context-bind time, and
//! `GetOwnerModuleFrom{Tcp,Udp}Entry` is the documented way to turn that into
//! a name — which Microsoft states "can be … a service name (such as 'RPC')".
//! Reading the blob as a raw service tag and calling `I_QueryTagInformation`
//! would be faster and is what System Informer does, but it is undocumented
//! and deliberately not used in v1 (research §3): nothing load-bearing here
//! is unsupported.
//!
//! Everything in this file runs on the metadata resolver lane. Both the table
//! fetch and the per-row call are documented as expensive — `netstat -b`, the
//! in-box consumer of the same machinery, warns it "can be time-consuming" —
//! which is exactly why a batch shares one table snapshot per (protocol,
//! family) and why none of it may ever touch the Engine thread.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");
const resolver = @import("resolver.zig");
const tables = @import("tables.zig");

/// Resolve a batch of sockets, writing each answer into `out[i]` (owned by
/// the caller; null where the socket could not be resolved). `out.len` must
/// equal `queries.len`.
///
/// Batching is the point: every query in the batch shares at most four table
/// fetches, and a table is only fetched if some query needs it.
pub fn resolveAll(
    gpa: std.mem.Allocator,
    queries: []const resolver.OwnerQuery,
    out: []?[]u8,
) void {
    std.debug.assert(out.len == queries.len);
    var owner_tables: OwnerTables = .init(gpa);
    defer owner_tables.deinit();
    for (queries, out) |q, *slot| slot.* = owner_tables.resolve(q);
}

/// The four extended owner-module tables, each fetched at most once and only
/// when something asks for it.
pub const OwnerTables = struct {
    gpa: std.mem.Allocator,
    slots: [4]Slot = @splat(.unfetched),

    const Kind = enum { tcp4, tcp6, udp4, udp6 };
    /// `failed` is distinct from `unfetched` so one failing table doesn't get
    /// re-queried by every remaining request in the batch.
    const Slot = union(enum) {
        unfetched,
        failed,
        buf: []align(8) u8,
    };

    pub fn init(gpa: std.mem.Allocator) OwnerTables {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *OwnerTables) void {
        for (self.slots) |slot| switch (slot) {
            .buf => |b| self.gpa.free(b),
            else => {},
        };
        self.slots = @splat(.unfetched);
    }

    /// The service-or-module name owning this socket, or null when no row
    /// matches, the row has no resolvable owner, or the table is unavailable.
    /// Caller owns the returned name.
    pub fn resolve(self: *OwnerTables, q: resolver.OwnerQuery) ?[]u8 {
        return switch (q.key.tuple.proto) {
            // TCP rows carry a concrete local *and* remote endpoint for every
            // conversation, so an exact match is the only correct one.
            .tcp => switch (q.key.tuple.family) {
                .v4 => self.resolveIn(win32.MIB_TCPROW_OWNER_MODULE, tcp4Matches, tcpName, false, .tcp4, q),
                .v6 => self.resolveIn(win32.MIB_TCP6ROW_OWNER_MODULE, tcp6Matches, tcp6Name, false, .tcp6, q),
            },
            .udp => switch (q.key.tuple.family) {
                .v4 => self.resolveIn(win32.MIB_UDPROW_OWNER_MODULE, udp4Matches, udpName, true, .udp4, q),
                .v6 => self.resolveIn(win32.MIB_UDP6ROW_OWNER_MODULE, udp6Matches, udp6Name, true, .udp6, q),
            },
            // There is no owner-module table for ICMP: IP Helper indexes
            // sockets, and ICMP has none (issue #27). Core settles ICMP Flows
            // without ever posting one of these, so this arm is the belt to
            // that braces — an ICMP query can only ever be answered "no".
            .icmp => null,
        };
    }

    fn resolveIn(
        self: *OwnerTables,
        comptime Row: type,
        comptime matches: fn (Row, resolver.OwnerQuery, bool) bool,
        comptime nameOf: fn (*Row, []align(8) u8) ?[]const u16,
        comptime wildcard_fallback: bool,
        kind: Kind,
        q: resolver.OwnerQuery,
    ) ?[]u8 {
        const buf = self.table(kind) orelse return null;
        const rows = tableRows(Row, buf) orelse return null;
        const row = findRow(Row, matches, wildcard_fallback, rows, q) orelse return null;
        // The info struct and the strings it points at both live in this
        // buffer, so the name must be copied out before it goes away. A
        // module name plus a full path cannot approach this size.
        var info_buf: [2048]u8 align(8) = undefined;
        const units = nameOf(row, &info_buf) orelse return null;
        // A non-elevated caller gets empty strings for protected processes
        // (documented). zPulsar is always elevated, so this is belt and
        // braces.
        if (units.len == 0) return null;
        return std.unicode.wtf16LeToWtf8Alloc(self.gpa, units) catch null;
    }

    fn table(self: *OwnerTables, kind: Kind) ?[]align(8) u8 {
        const slot = &self.slots[@intFromEnum(kind)];
        switch (slot.*) {
            .buf => |b| return b,
            .failed => return null,
            .unfetched => {},
        }
        const class: tables.TableClass = switch (kind) {
            // ALL, not CONNECTIONS: a socket may be listening rather than
            // connected and still be the one that owns the Flow.
            .tcp4, .tcp6 => .{ .tcp = .OWNER_MODULE_ALL },
            .udp4, .udp6 => .{ .udp = .OWNER_MODULE },
        };
        const af: u32 = switch (kind) {
            .tcp4, .udp4 => win32.AF_INET,
            .tcp6, .udp6 => win32.AF_INET6,
        };
        const buf = tables.fetchExtended(self.gpa, class, af) catch {
            slot.* = .failed;
            return null;
        };
        slot.* = .{ .buf = buf };
        return buf;
    }
};

/// The rows of an extended owner-module table. Unlike the OWNER_PID tables
/// these start at offset 8, not 4: the u64 `OwningModuleInfo` forces the row
/// type to 8-byte alignment, so the count is followed by 4 bytes of padding.
/// Null when the buffer doesn't hold the rows it claims.
fn tableRows(comptime Row: type, buf: []align(8) u8) ?[]Row {
    comptime std.debug.assert(@alignOf(Row) == 8);
    if (buf.len < 8) return null;
    const n = std.mem.readInt(u32, buf[0..4], .little);
    const rows_bytes = buf[8..];
    if (rows_bytes.len / @sizeOf(Row) < n) return null;
    return @as([*]Row, @ptrCast(@alignCast(rows_bytes.ptr)))[0..n];
}

/// The row answering for this socket. Exact local addresses first, and only
/// then — for UDP — a wildcard bind, so a socket bound to one interface is
/// never answered for by an any-address row sharing its port.
fn findRow(
    comptime Row: type,
    comptime matches: fn (Row, resolver.OwnerQuery, bool) bool,
    comptime wildcard_fallback: bool,
    rows: []Row,
    q: resolver.OwnerQuery,
) ?*Row {
    for (rows) |*row| {
        if (matches(row.*, q, false)) return row;
    }
    if (!wildcard_fallback) return null;
    for (rows) |*row| {
        if (matches(row.*, q, true)) return row;
    }
    return null;
}

/// Does this row describe the socket the query asks about? Beyond the
/// endpoints, two guards keep a stale row from answering for the wrong
/// process (research §5 case 4): the row's owning PID must be the Flow's, and
/// its context bind must not predate the process instance that owns the Flow
/// — otherwise the row belongs to a previous holder of a reused PID.
fn ownerMatches(pid: u32, create_time: u64, q: resolver.OwnerQuery, bound_at: i64) bool {
    if (pid != q.key.pid) return false;
    if (create_time == 0 or bound_at <= 0) return true; // nothing to compare
    return @as(u64, @intCast(bound_at)) >= create_time;
}

/// A socket bound to the any-address genuinely owns every interface, while
/// the Flow's local address came from a datagram and names one of them. With
/// `wildcard` set, such a row answers for it — without this, the ordinary
/// `0.0.0.0`-bound UDP service resolves to nothing at all.
fn localMatches(row_addr: [16]u8, flow_addr: [16]u8, wildcard: bool) bool {
    if (std.mem.eql(u8, &row_addr, &flow_addr)) return true;
    return wildcard and std.mem.allEqual(u8, &row_addr, 0);
}

fn tcp4Matches(row: win32.MIB_TCPROW_OWNER_MODULE, q: resolver.OwnerQuery, wildcard: bool) bool {
    const t = q.key.tuple;
    return localMatches(tables.addr4(row.dwLocalAddr), t.local_addr, wildcard) and
        tables.portFromDword(row.dwLocalPort) == t.local_port and
        std.mem.eql(u8, &tables.addr4(row.dwRemoteAddr), &t.remote_addr) and
        tables.portFromDword(row.dwRemotePort) == t.remote_port and
        ownerMatches(row.dwOwningPid, q.create_time, q, row.liCreateTimestamp.QuadPart);
}

fn tcp6Matches(row: win32.MIB_TCP6ROW_OWNER_MODULE, q: resolver.OwnerQuery, wildcard: bool) bool {
    const t = q.key.tuple;
    return localMatches(row.ucLocalAddr, t.local_addr, wildcard) and
        tables.portFromDword(row.dwLocalPort) == t.local_port and
        std.mem.eql(u8, &row.ucRemoteAddr, &t.remote_addr) and
        tables.portFromDword(row.dwRemotePort) == t.remote_port and
        ownerMatches(row.dwOwningPid, q.create_time, q, row.liCreateTimestamp.QuadPart);
}

/// UDP rows know only the local endpoint, so a Flow's real remote endpoint
/// plays no part — one bound socket answers for every conversation on it.
fn udp4Matches(row: win32.MIB_UDPROW_OWNER_MODULE, q: resolver.OwnerQuery, wildcard: bool) bool {
    const t = q.key.tuple;
    return localMatches(tables.addr4(row.dwLocalAddr), t.local_addr, wildcard) and
        tables.portFromDword(row.dwLocalPort) == t.local_port and
        ownerMatches(row.dwOwningPid, q.create_time, q, row.liCreateTimestamp.QuadPart);
}

fn udp6Matches(row: win32.MIB_UDP6ROW_OWNER_MODULE, q: resolver.OwnerQuery, wildcard: bool) bool {
    const t = q.key.tuple;
    return localMatches(row.ucLocalAddr, t.local_addr, wildcard) and
        tables.portFromDword(row.dwLocalPort) == t.local_port and
        ownerMatches(row.dwOwningPid, q.create_time, q, row.liCreateTimestamp.QuadPart);
}

/// `GetOwnerModuleFrom*Entry` writes a TCPIP_OWNER_MODULE_BASIC_INFO at the
/// head of `info_buf` with pointers to strings further inside it, so the
/// returned units alias the caller's buffer. `ERROR_NOT_FOUND` — the owning
/// PID is 0, or the endpoint's owner is already gone — is an ordinary miss.
fn moduleName(
    comptime Row: type,
    comptime call: fn (
        ?*Row,
        win32.TCPIP_OWNER_MODULE_INFO_CLASS,
        ?*anyopaque,
        ?*u32,
    ) callconv(.winapi) u32,
    row: *Row,
    info_buf: []align(8) u8,
) ?[]const u16 {
    var size: u32 = @intCast(info_buf.len);
    if (call(row, win32.TCPIP_OWNER_MODULE_INFO_BASIC, info_buf.ptr, &size) !=
        win32.ERROR_SUCCESS) return null;
    if (size < @sizeOf(win32.TCPIP_OWNER_MODULE_BASIC_INFO)) return null;
    const info: *const win32.TCPIP_OWNER_MODULE_BASIC_INFO = @ptrCast(@alignCast(info_buf.ptr));
    const name = info.pModuleName orelse return null;
    return std.mem.sliceTo(@as([*:0]const u16, @ptrCast(name)), 0);
}

fn tcpName(row: *win32.MIB_TCPROW_OWNER_MODULE, info_buf: []align(8) u8) ?[]const u16 {
    return moduleName(win32.MIB_TCPROW_OWNER_MODULE, win32.GetOwnerModuleFromTcpEntry, row, info_buf);
}

fn tcp6Name(row: *win32.MIB_TCP6ROW_OWNER_MODULE, info_buf: []align(8) u8) ?[]const u16 {
    return moduleName(win32.MIB_TCP6ROW_OWNER_MODULE, win32.GetOwnerModuleFromTcp6Entry, row, info_buf);
}

fn udpName(row: *win32.MIB_UDPROW_OWNER_MODULE, info_buf: []align(8) u8) ?[]const u16 {
    return moduleName(win32.MIB_UDPROW_OWNER_MODULE, win32.GetOwnerModuleFromUdpEntry, row, info_buf);
}

fn udp6Name(row: *win32.MIB_UDP6ROW_OWNER_MODULE, info_buf: []align(8) u8) ?[]const u16 {
    return moduleName(win32.MIB_UDP6ROW_OWNER_MODULE, win32.GetOwnerModuleFromUdp6Entry, row, info_buf);
}

// ---------------------------------------------------------------------------
// Tests — synthetic table buffers, as in tables.zig: which row answers for a
// socket is the whole correctness question here, and it is decidable without
// a live machine. The `GetOwnerModuleFrom*Entry` call itself needs real
// sockets and is exercised by the headless rig.
// ---------------------------------------------------------------------------

/// An owner-module table exactly as the OS lays it out: count, 4 bytes of
/// padding, then 8-aligned rows.
fn testTable(comptime Row: type, gpa: std.mem.Allocator, rows: []const Row) ![]align(8) u8 {
    const buf = try gpa.alignedAlloc(u8, .of(u64), 8 + rows.len * @sizeOf(Row));
    @memset(buf, 0);
    std.mem.writeInt(u32, buf[0..4], @intCast(rows.len), .little);
    @memcpy(buf[8..], std.mem.sliceAsBytes(rows));
    return buf;
}

fn testPortDword(port: u16) u32 {
    return @as(u32, std.mem.nativeToBig(u16, port));
}

fn testQuery(proto: event.Proto, family: event.Family, pid: u32, create_time: u64) resolver.OwnerQuery {
    return .{
        .generation = 1,
        .create_time = create_time,
        .key = .{ .pid = pid, .tuple = .{
            .proto = proto,
            .family = family,
            .local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0)),
            .remote_addr = if (proto == .udp)
                @splat(0)
            else
                [4]u8{ 93, 184, 216, 34 } ++ @as([12]u8, @splat(0)),
            .local_port = 51000,
            .remote_port = if (proto == .udp) 0 else 443,
        } },
    };
}

fn testTcp4Row(pid: u32, local_port: u16, bound_at: i64) win32.MIB_TCPROW_OWNER_MODULE {
    return .{
        .dwState = @intFromEnum(win32.MIB_TCP_STATE.ESTAB),
        .dwLocalAddr = std.mem.bytesToValue(u32, &[4]u8{ 192, 168, 1, 2 }),
        .dwLocalPort = testPortDword(local_port),
        .dwRemoteAddr = std.mem.bytesToValue(u32, &[4]u8{ 93, 184, 216, 34 }),
        .dwRemotePort = testPortDword(443),
        .dwOwningPid = pid,
        .liCreateTimestamp = .{ .QuadPart = bound_at },
        .OwningModuleInfo = @splat(0),
    };
}

/// The row `resolve` would hand to `GetOwnerModuleFromTcpEntry`, if any.
fn findTcp4(buf: []align(8) u8, q: resolver.OwnerQuery) ?*win32.MIB_TCPROW_OWNER_MODULE {
    const rows = tableRows(win32.MIB_TCPROW_OWNER_MODULE, buf) orelse return null;
    return findRow(win32.MIB_TCPROW_OWNER_MODULE, tcp4Matches, false, rows, q);
}

/// The UDP twin, wildcard fallback included — exactly what `resolve` does.
fn findUdp4(buf: []align(8) u8, q: resolver.OwnerQuery) ?*win32.MIB_UDPROW_OWNER_MODULE {
    const rows = tableRows(win32.MIB_UDPROW_OWNER_MODULE, buf) orelse return null;
    return findRow(win32.MIB_UDPROW_OWNER_MODULE, udp4Matches, true, rows, q);
}

fn testUdp4Row(local: [4]u8, local_port: u16, pid: u32) win32.MIB_UDPROW_OWNER_MODULE {
    return .{
        .dwLocalAddr = std.mem.bytesToValue(u32, &local),
        .dwLocalPort = testPortDword(local_port),
        .dwOwningPid = pid,
        .liCreateTimestamp = .{ .QuadPart = 5000 },
        .Anonymous = .{ .dwFlags = 0 },
        .OwningModuleInfo = @splat(0),
    };
}

test "a socket matches only its own row, by full tuple and owning PID" {
    const gpa = std.testing.allocator;
    const buf = try testTable(win32.MIB_TCPROW_OWNER_MODULE, gpa, &.{
        testTcp4Row(900, 51001, 5000), // same host, a different socket
        testTcp4Row(900, 51000, 5000), // the one
        testTcp4Row(901, 51000, 5000), // same tuple, a different process
    });
    defer gpa.free(buf);

    const hit = findTcp4(buf, testQuery(.tcp, .v4, 900, 1000)).?;
    try std.testing.expectEqual(@as(u16, 51000), tables.portFromDword(hit.dwLocalPort));
    try std.testing.expectEqual(@as(u32, 900), hit.dwOwningPid);

    // A PID that owns no row in the table resolves to nothing at all —
    // never to whichever row happens to share the tuple.
    try std.testing.expectEqual(
        @as(?*win32.MIB_TCPROW_OWNER_MODULE, null),
        findTcp4(buf, testQuery(.tcp, .v4, 902, 1000)),
    );
}

test "a row bound before the process started belongs to the PID's last holder" {
    const gpa = std.testing.allocator;
    // Context bind at 500, but the Flow's process instance started at 1000:
    // the row is a remnant of whoever held this PID before.
    const buf = try testTable(win32.MIB_TCPROW_OWNER_MODULE, gpa, &.{testTcp4Row(900, 51000, 500)});
    defer gpa.free(buf);
    try std.testing.expectEqual(
        @as(?*win32.MIB_TCPROW_OWNER_MODULE, null),
        findTcp4(buf, testQuery(.tcp, .v4, 900, 1000)),
    );

    // Bound after the process started: this one is genuinely its socket.
    const fresh = try testTable(win32.MIB_TCPROW_OWNER_MODULE, gpa, &.{testTcp4Row(900, 51000, 1500)});
    defer gpa.free(fresh);
    try std.testing.expect(findTcp4(fresh, testQuery(.tcp, .v4, 900, 1000)) != null);

    // A row with no timestamp, or a Flow whose process start is unknown,
    // keeps the endpoint match rather than discarding it.
    const undated = try testTable(win32.MIB_TCPROW_OWNER_MODULE, gpa, &.{testTcp4Row(900, 51000, 0)});
    defer gpa.free(undated);
    try std.testing.expect(findTcp4(undated, testQuery(.tcp, .v4, 900, 1000)) != null);
    try std.testing.expect(findTcp4(fresh, testQuery(.tcp, .v4, 900, 0)) != null);
}

test "UDP rows match on the local endpoint alone" {
    const gpa = std.testing.allocator;
    const rows = [_]win32.MIB_UDPROW_OWNER_MODULE{testUdp4Row(.{ 192, 168, 1, 2 }, 51000, 900)};
    const buf = try testTable(win32.MIB_UDPROW_OWNER_MODULE, gpa, &rows);
    defer gpa.free(buf);
    const table = tableRows(win32.MIB_UDPROW_OWNER_MODULE, buf).?;

    // The Flow key carries the real remote endpoint; the table has none, and
    // matching must not care.
    var q = testQuery(.udp, .v4, 900, 1000);
    q.key.tuple.remote_addr = [4]u8{ 8, 8, 8, 8 } ++ @as([12]u8, @splat(0));
    q.key.tuple.remote_port = 53;
    try std.testing.expect(udp4Matches(table[0], q, false));

    q.key.tuple.local_port = 51001;
    try std.testing.expect(!udp4Matches(table[0], q, false));
}

test "a wildcard-bound UDP socket answers for a datagram on a real interface" {
    const gpa = std.testing.allocator;
    // The ordinary shape of a UDP service: bound to 0.0.0.0, while the ETW
    // datagram that opened the Flow names the interface it actually went out
    // of. Without the wildcard pass these never meet and every such Flow
    // silently falls to the tier 3 fallback.
    const buf = try testTable(win32.MIB_UDPROW_OWNER_MODULE, gpa, &.{
        testUdp4Row(.{ 0, 0, 0, 0 }, 5353, 900),
    });
    defer gpa.free(buf);

    var q = testQuery(.udp, .v4, 900, 1000);
    q.key.tuple.local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0));
    q.key.tuple.local_port = 5353;
    try std.testing.expect(findUdp4(buf, q) != null);

    // A different PID still owns nothing here, wildcard or not.
    var other = q;
    other.key.pid = 901;
    try std.testing.expectEqual(@as(?*win32.MIB_UDPROW_OWNER_MODULE, null), findUdp4(buf, other));
}

test "an interface-bound UDP row wins over a wildcard row on the same port" {
    const gpa = std.testing.allocator;
    // Same process, same port, two binds. The specific one owns this
    // datagram; the wildcard row must not be allowed to answer first.
    const buf = try testTable(win32.MIB_UDPROW_OWNER_MODULE, gpa, &.{
        testUdp4Row(.{ 0, 0, 0, 0 }, 5353, 900),
        testUdp4Row(.{ 192, 168, 1, 2 }, 5353, 900),
    });
    defer gpa.free(buf);

    var q = testQuery(.udp, .v4, 900, 1000);
    q.key.tuple.local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0));
    q.key.tuple.local_port = 5353;
    const hit = findUdp4(buf, q).?;
    try std.testing.expectEqualSlices(
        u8,
        &[4]u8{ 192, 168, 1, 2 },
        std.mem.asBytes(&hit.dwLocalAddr),
    );
}

test "IPv6 rows match on their raw 16-byte addresses" {
    const gpa = std.testing.allocator;
    const local = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const remote = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
    const rows = [_]win32.MIB_TCP6ROW_OWNER_MODULE{.{
        .ucLocalAddr = local,
        .dwLocalScopeId = 0,
        .dwLocalPort = testPortDword(51000),
        .ucRemoteAddr = remote,
        .dwRemoteScopeId = 0,
        .dwRemotePort = testPortDword(443),
        .dwState = @intFromEnum(win32.MIB_TCP_STATE.ESTAB),
        .dwOwningPid = 900,
        .liCreateTimestamp = .{ .QuadPart = 5000 },
        .OwningModuleInfo = @splat(0),
    }};
    const buf = try testTable(win32.MIB_TCP6ROW_OWNER_MODULE, gpa, &rows);
    defer gpa.free(buf);
    const table = tableRows(win32.MIB_TCP6ROW_OWNER_MODULE, buf).?;

    var q = testQuery(.tcp, .v6, 900, 1000);
    q.key.tuple.local_addr = local;
    q.key.tuple.remote_addr = remote;
    try std.testing.expect(tcp6Matches(table[0], q, false));

    // One byte of the remote address apart is a different conversation.
    q.key.tuple.remote_addr[15] = 0x11;
    try std.testing.expect(!tcp6Matches(table[0], q, false));
}

test "a buffer that doesn't hold the rows it claims is rejected" {
    var buf: [8 + @sizeOf(win32.MIB_TCPROW_OWNER_MODULE)]u8 align(8) = @splat(0);
    std.mem.writeInt(u32, buf[0..4], 4, .little); // claims 4 rows, holds 1
    try std.testing.expectEqual(
        @as(?[]win32.MIB_TCPROW_OWNER_MODULE, null),
        tableRows(win32.MIB_TCPROW_OWNER_MODULE, &buf),
    );

    // An empty table is well-formed and simply matches nothing.
    var empty: [8]u8 align(8) = @splat(0);
    try std.testing.expectEqual(
        @as(usize, 0),
        tableRows(win32.MIB_TCPROW_OWNER_MODULE, &empty).?.len,
    );
    var truncated: [4]u8 align(8) = @splat(0);
    try std.testing.expectEqual(
        @as(?[]win32.MIB_TCPROW_OWNER_MODULE, null),
        tableRows(win32.MIB_TCPROW_OWNER_MODULE, &truncated),
    );
}
