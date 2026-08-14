//! Cold-start snapshot of the TCP/UDP owner tables (IP Helper). The walking
//! skeleton only surfaces row counts; the full row parse arrives with the
//! flow-table ticket.

const std = @import("std");
const win32 = @import("win32");

/// Row counts of the four owner tables the Engine cold-starts from
/// (spec issue #18 "Cold start"; docs/research/etw-tcp-udp-pipeline.md §4).
/// Not to be confused with the glossary's Snapshot (the Engine's published
/// state) — this is the raw IP Helper table probe.
pub const TableCounts = struct {
    tcp4: u32,
    tcp6: u32,
    udp4: u32,
    udp6: u32,
};

pub const SnapshotError = error{ OutOfMemory, TableQueryFailed };

/// Query all four TCP/UDP owner-PID tables and return their row counts.
pub fn snapshotTableCounts(gpa: std.mem.Allocator) SnapshotError!TableCounts {
    return .{
        .tcp4 = try tableRowCount(gpa, .tcp, win32.AF_INET),
        .tcp6 = try tableRowCount(gpa, .tcp, win32.AF_INET6),
        .udp4 = try tableRowCount(gpa, .udp, win32.AF_INET),
        .udp6 = try tableRowCount(gpa, .udp, win32.AF_INET6),
    };
}

/// All four OWNER_PID table layouts lead with dwNumEntries: u32
/// (comptime-asserted in the facade).
pub fn rowCountFromBuffer(buf: []const u8) u32 {
    std.debug.assert(buf.len >= @sizeOf(u32));
    return std.mem.readInt(u32, buf[0..4], .little);
}

const Protocol = enum { tcp, udp };

/// Probe-then-fill; retried because the table can grow between the size
/// probe and the fill call.
fn tableRowCount(gpa: std.mem.Allocator, comptime protocol: Protocol, af: u32) SnapshotError!u32 {
    var size: u32 = 0;
    var rc = getTable(protocol, null, &size, af);
    var attempts: u8 = 0;
    while (rc == win32.ERROR_INSUFFICIENT_BUFFER and attempts < 4) : (attempts += 1) {
        const buf = try gpa.alignedAlloc(u8, .of(u32), size);
        defer gpa.free(buf);
        rc = getTable(protocol, buf.ptr, &size, af);
        if (rc == win32.ERROR_SUCCESS) return rowCountFromBuffer(buf);
    }
    return error.TableQueryFailed;
}

fn getTable(comptime protocol: Protocol, buf: ?*anyopaque, size: *u32, af: u32) u32 {
    return switch (protocol) {
        .tcp => win32.GetExtendedTcpTable(buf, size, win32.FALSE, af, .OWNER_PID_ALL, 0),
        .udp => win32.GetExtendedUdpTable(buf, size, win32.FALSE, af, .OWNER_PID, 0),
    };
}

test "row count is the leading dwNumEntries of a table buffer" {
    // A MIB_UDPTABLE_OWNER_PID buffer with 3 rows: dwNumEntries then
    // 3 x 12-byte rows (values irrelevant to the count).
    var buf: [4 + 3 * 12]u8 = @splat(0xaa);
    std.mem.writeInt(u32, buf[0..4], 3, .little);
    try std.testing.expectEqual(@as(u32, 3), rowCountFromBuffer(&buf));
}
