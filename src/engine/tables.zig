//! Cold-start snapshot of the TCP/UDP owner tables (IP Helper), parsed into
//! seeded connections keyed the same way as live events (spec issue #18
//! "Cold start"; docs/research/etw-tcp-udp-pipeline.md §4). Ports and
//! addresses in the tables are network byte order, exactly like event
//! payloads, so both sources share one normalization (event.ConnKey).
//! Not to be confused with the glossary's Snapshot (the Engine's published
//! state) — this is the raw IP Helper table probe.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");

/// One owner-table row: who owns which connection right now. The seed's only
/// job is presence — attribution never depends on it (every data event
/// carries its own PID).
pub const SeededConn = struct {
    key: event.ConnKey,
    pid: u32,
};

pub const SnapshotError = error{ OutOfMemory, TableQueryFailed };

/// Query all four owner-PID tables and return their rows as seeded
/// connections. Caller owns the slice.
pub fn snapshotConnections(gpa: std.mem.Allocator) SnapshotError![]SeededConn {
    var list: std.ArrayList(SeededConn) = .empty;
    errdefer list.deinit(gpa);
    try appendTable(&list, gpa, .tcp, win32.AF_INET);
    try appendTable(&list, gpa, .tcp, win32.AF_INET6);
    try appendTable(&list, gpa, .udp, win32.AF_INET);
    try appendTable(&list, gpa, .udp, win32.AF_INET6);
    return list.toOwnedSlice(gpa);
}

const Protocol = enum { tcp, udp };

fn appendTable(
    list: *std.ArrayList(SeededConn),
    gpa: std.mem.Allocator,
    comptime protocol: Protocol,
    af: u32,
) SnapshotError!void {
    const buf = try fetchTable(gpa, protocol, af);
    defer gpa.free(buf);
    const ok = switch (protocol) {
        .tcp => switch (af) {
            win32.AF_INET => try appendRows(win32.MIB_TCPROW_OWNER_PID, tcp4Conn, list, gpa, buf),
            else => try appendRows(win32.MIB_TCP6ROW_OWNER_PID, tcp6Conn, list, gpa, buf),
        },
        .udp => switch (af) {
            win32.AF_INET => try appendRows(win32.MIB_UDPROW_OWNER_PID, udp4Conn, list, gpa, buf),
            else => try appendRows(win32.MIB_UDP6ROW_OWNER_PID, udp6Conn, list, gpa, buf),
        },
    };
    if (!ok) return error.TableQueryFailed;
}

/// Probe-then-fill; retried because the table can grow between the size
/// probe and the fill call.
fn fetchTable(
    gpa: std.mem.Allocator,
    comptime protocol: Protocol,
    af: u32,
) SnapshotError![]align(4) u8 {
    var size: u32 = 0;
    var rc = getTable(protocol, null, &size, af);
    var attempts: u8 = 0;
    while (rc == win32.ERROR_INSUFFICIENT_BUFFER and attempts < 4) : (attempts += 1) {
        const buf = try gpa.alignedAlloc(u8, .of(u32), size);
        errdefer gpa.free(buf);
        rc = getTable(protocol, buf.ptr, &size, af);
        if (rc == win32.ERROR_SUCCESS) return buf;
        gpa.free(buf);
    }
    return error.TableQueryFailed;
}

fn getTable(comptime protocol: Protocol, buf: ?*anyopaque, size: *u32, af: u32) u32 {
    return switch (protocol) {
        .tcp => win32.GetExtendedTcpTable(buf, size, win32.FALSE, af, .OWNER_PID_ALL, 0),
        .udp => win32.GetExtendedUdpTable(buf, size, win32.FALSE, af, .OWNER_PID, 0),
    };
}

/// All four OWNER_PID tables share the shape dwNumEntries: u32 followed by
/// packed rows (comptime-asserted in the facade). Returns false when the
/// buffer doesn't hold the rows it claims.
fn appendRows(
    comptime Row: type,
    comptime convert: fn (Row) SeededConn,
    list: *std.ArrayList(SeededConn),
    gpa: std.mem.Allocator,
    buf: []align(4) const u8,
) error{OutOfMemory}!bool {
    if (buf.len < 4) return false;
    const n = std.mem.readInt(u32, buf[0..4], .little);
    const rows_bytes = buf[4..];
    if (rows_bytes.len / @sizeOf(Row) < n) return false;
    const rows = @as([*]const Row, @ptrCast(@alignCast(rows_bytes.ptr)))[0..n];
    try list.ensureUnusedCapacity(gpa, n);
    for (rows) |row| list.appendAssumeCapacity(convert(row));
    return true;
}

/// The port DWORDs hold the u16 port in network byte order in their low
/// bytes ("in network byte order"; upper bytes may be uninitialized —
/// MIB_TCPROW_OWNER_PID docs), i.e. the classic ntohs((u_short)dwPort).
fn portFromDword(dw: u32) u16 {
    return std.mem.bigToNative(u16, @truncate(dw));
}

/// The address DWORD is the in_addr value: its memory bytes are already
/// network order.
fn addr4(dw: u32) [16]u8 {
    return std.mem.toBytes(dw) ++ @as([12]u8, @splat(0));
}

fn tcp4Conn(row: win32.MIB_TCPROW_OWNER_PID) SeededConn {
    return .{ .pid = row.dwOwningPid, .key = .{
        .proto = .tcp,
        .family = .v4,
        .local_addr = addr4(row.dwLocalAddr),
        .remote_addr = addr4(row.dwRemoteAddr),
        .local_port = portFromDword(row.dwLocalPort),
        .remote_port = portFromDword(row.dwRemotePort),
    } };
}

fn tcp6Conn(row: win32.MIB_TCP6ROW_OWNER_PID) SeededConn {
    return .{ .pid = row.dwOwningPid, .key = .{
        .proto = .tcp,
        .family = .v6,
        .local_addr = row.ucLocalAddr,
        .remote_addr = row.ucRemoteAddr,
        .local_port = portFromDword(row.dwLocalPort),
        .remote_port = portFromDword(row.dwRemotePort),
    } };
}

/// UDP rows are local-endpoint only; the zeroed remote side is exactly the
/// event-side UDP key normalization (event.connKey).
fn udp4Conn(row: win32.MIB_UDPROW_OWNER_PID) SeededConn {
    return .{ .pid = row.dwOwningPid, .key = .{
        .proto = .udp,
        .family = .v4,
        .local_addr = addr4(row.dwLocalAddr),
        .remote_addr = @splat(0),
        .local_port = portFromDword(row.dwLocalPort),
        .remote_port = 0,
    } };
}

fn udp6Conn(row: win32.MIB_UDP6ROW_OWNER_PID) SeededConn {
    return .{ .pid = row.dwOwningPid, .key = .{
        .proto = .udp,
        .family = .v6,
        .local_addr = row.ucLocalAddr,
        .remote_addr = @splat(0),
        .local_port = portFromDword(row.dwLocalPort),
        .remote_port = 0,
    } };
}

// ---------------------------------------------------------------------------
// Tests — synthetic table buffers, since the live tables need a real machine.
// ---------------------------------------------------------------------------

/// dwPort encoding as the OS produces it: network-order u16 in the low bytes.
fn testPortDword(port: u16) u32 {
    return @as(u32, std.mem.nativeToBig(u16, port));
}

fn testTableBuffer(comptime Row: type, gpa: std.mem.Allocator, rows: []const Row) ![]align(4) u8 {
    const buf = try gpa.alignedAlloc(u8, .of(u32), 4 + rows.len * @sizeOf(Row));
    std.mem.writeInt(u32, buf[0..4], @intCast(rows.len), .little);
    @memcpy(buf[4..], std.mem.sliceAsBytes(rows));
    return buf;
}

test "tcp4 rows parse into normalized seeded connections" {
    const rows = [_]win32.MIB_TCPROW_OWNER_PID{
        .{
            .dwState = 5, // ESTABLISHED
            .dwLocalAddr = std.mem.bytesToValue(u32, &[4]u8{ 192, 168, 1, 2 }),
            .dwLocalPort = testPortDword(51000),
            .dwRemoteAddr = std.mem.bytesToValue(u32, &[4]u8{ 93, 184, 216, 34 }),
            .dwRemotePort = testPortDword(443),
            .dwOwningPid = 4242,
        },
        .{
            .dwState = 2, // LISTEN
            .dwLocalAddr = 0,
            .dwLocalPort = testPortDword(8080),
            .dwRemoteAddr = 0,
            .dwRemotePort = 0,
            .dwOwningPid = 1000,
        },
    };
    const buf = try testTableBuffer(win32.MIB_TCPROW_OWNER_PID, std.testing.allocator, &rows);
    defer std.testing.allocator.free(buf);

    var list: std.ArrayList(SeededConn) = .empty;
    defer list.deinit(std.testing.allocator);
    try std.testing.expect(try appendRows(win32.MIB_TCPROW_OWNER_PID, tcp4Conn, &list, std.testing.allocator, buf));

    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    const c = list.items[0];
    try std.testing.expectEqual(@as(u32, 4242), c.pid);
    try std.testing.expectEqual(event.Proto.tcp, c.key.proto);
    try std.testing.expectEqual(event.Family.v4, c.key.family);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 2 }, c.key.local_addr[0..4]);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 93, 184, 216, 34 }, c.key.remote_addr[0..4]);
    try std.testing.expectEqual(@as(u16, 51000), c.key.local_port);
    try std.testing.expectEqual(@as(u16, 443), c.key.remote_port);
    try std.testing.expectEqual(@as(u16, 8080), list.items[1].key.local_port);
}

test "tcp6 rows keep raw 16-byte addresses" {
    const local = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const remote = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
    const rows = [_]win32.MIB_TCP6ROW_OWNER_PID{.{
        .ucLocalAddr = local,
        .dwLocalScopeId = 3,
        .dwLocalPort = testPortDword(51001),
        .ucRemoteAddr = remote,
        .dwRemoteScopeId = 0,
        .dwRemotePort = testPortDword(993),
        .dwState = 5,
        .dwOwningPid = 77,
    }};
    const buf = try testTableBuffer(win32.MIB_TCP6ROW_OWNER_PID, std.testing.allocator, &rows);
    defer std.testing.allocator.free(buf);

    var list: std.ArrayList(SeededConn) = .empty;
    defer list.deinit(std.testing.allocator);
    try std.testing.expect(try appendRows(win32.MIB_TCP6ROW_OWNER_PID, tcp6Conn, &list, std.testing.allocator, buf));

    const c = list.items[0];
    try std.testing.expectEqual(event.Family.v6, c.key.family);
    try std.testing.expectEqualSlices(u8, &local, &c.key.local_addr);
    try std.testing.expectEqualSlices(u8, &remote, &c.key.remote_addr);
    try std.testing.expectEqual(@as(u16, 993), c.key.remote_port);
}

test "udp rows seed local-only keys matching the event-side normalization" {
    const rows4 = [_]win32.MIB_UDPROW_OWNER_PID{.{
        .dwLocalAddr = std.mem.bytesToValue(u32, &[4]u8{ 10, 0, 0, 5 }),
        .dwLocalPort = testPortDword(53),
        .dwOwningPid = 555,
    }};
    const buf = try testTableBuffer(win32.MIB_UDPROW_OWNER_PID, std.testing.allocator, &rows4);
    defer std.testing.allocator.free(buf);

    var list: std.ArrayList(SeededConn) = .empty;
    defer list.deinit(std.testing.allocator);
    try std.testing.expect(try appendRows(win32.MIB_UDPROW_OWNER_PID, udp4Conn, &list, std.testing.allocator, buf));

    const c = list.items[0];
    // The seeded key must equal event.connKey of a matching live event —
    // that's the dedupe contract.
    const from_event = event.connKey(.{
        .op = .send,
        .proto = .udp,
        .family = .v4,
        .pid = 555,
        .size = 10,
        .local_addr = [4]u8{ 10, 0, 0, 5 } ++ @as([12]u8, @splat(0)),
        .remote_addr = [4]u8{ 8, 8, 8, 8 } ++ @as([12]u8, @splat(0)),
        .local_port = 53,
        .remote_port = 12345,
        .timestamp_qpc = 0,
    });
    try std.testing.expectEqual(from_event, c.key);
}

test "a buffer that doesn't hold the rows it claims is rejected" {
    var buf: [4 + @sizeOf(win32.MIB_UDPROW_OWNER_PID)]u8 align(4) = @splat(0);
    std.mem.writeInt(u32, buf[0..4], 5, .little); // claims 5 rows, holds 1
    var list: std.ArrayList(SeededConn) = .empty;
    defer list.deinit(std.testing.allocator);
    try std.testing.expect(!try appendRows(win32.MIB_UDPROW_OWNER_PID, udp4Conn, &list, std.testing.allocator, &buf));
}

test "an empty table parses to no connections" {
    var buf: [4]u8 align(4) = @splat(0);
    var list: std.ArrayList(SeededConn) = .empty;
    defer list.deinit(std.testing.allocator);
    try std.testing.expect(try appendRows(win32.MIB_TCPROW_OWNER_PID, tcp4Conn, &list, std.testing.allocator, &buf));
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}
