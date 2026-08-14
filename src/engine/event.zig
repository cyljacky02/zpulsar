//! The fixed-size record the ETW consumer thread parses events into and
//! pushes onto the SPSC ring (spec issue #18 "Architecture and threading";
//! ADR-0002). One shared normalization for both event payloads and IP Helper
//! table rows: addresses stay raw network-order bytes, ports are converted to
//! host order once, at parse time.

const std = @import("std");

pub const Proto = enum(u8) { tcp, udp };
pub const Family = enum(u8) { v4, v6 };

/// What the Engine does with the record: send/recv accumulate In-session
/// Totals; connect/disconnect maintain the connection list. Events excluded
/// from totals (retransmit, protocol copy) never become records at all.
pub const Op = enum(u8) { send, recv, connect, disconnect };

pub const NetEvent = struct {
    op: Op,
    proto: Proto,
    family: Family,
    pid: u32,
    /// Bytes of the transport operation; 0 for lifecycle events.
    size: u32,
    /// Raw network-order bytes; v4 occupies the first 4 bytes, rest zero.
    local_addr: [16]u8,
    remote_addr: [16]u8,
    /// Host byte order.
    local_port: u16,
    remote_port: u16,
    /// EVENT_HEADER.TimeStamp. The session clock is QPC, but the consumer
    /// does not set PROCESS_TRACE_MODE_RAW_TIMESTAMP, so ETW delivers it
    /// converted to FILETIME (docs/research/kernel-process-etw.md §3) —
    /// directly comparable to ProcessEvent create/exit times.
    timestamp_ft: i64,
};

comptime {
    // The ring is sized as 16 Ki x ~64 B (spec); keep the record within that.
    std.debug.assert(@sizeOf(NetEvent) <= 64);
}

/// Longest image name kept: an NT device prefix (`\Device\HarddiskVolumeNN\`,
/// ~25 units) plus a MAX_PATH DOS path. Longer names truncate — a display
/// concern only; the row key never involves the name.
pub const max_image_name_units = 288;

pub const ProcessKind = enum(u8) { start, stop, rundown };

/// Fixed-size Kernel-Process record for the process ring
/// (docs/research/kernel-process-etw.md). Process events are low-volume
/// (tens/s worst case), so the inline name buffer is affordable and keeps the
/// consumer thread allocation-free.
pub const ProcessEvent = struct {
    kind: ProcessKind,
    pid: u32,
    /// Raw payload CreateTime FILETIME — the other half of the Process Row
    /// key (pid, create_time), bit-identical across start/stop/rundown.
    create_time: u64,
    /// Raw payload ExitTime FILETIME; stop events only, 0 otherwise.
    exit_time: u64,
    /// UTF-16 units of `name_buf` in use. Always 0 for stop events: the
    /// stop-event name is ANSI and kernel-truncated — never displayed
    /// (research §2.4).
    name_len: u16,
    /// Image name from start/rundown payloads: full NT device path, or a
    /// bare name for kernel/minimal processes (System, Registry, …).
    name_buf: [max_image_name_units]u16,

    pub fn name(self: *const ProcessEvent) []const u16 {
        return self.name_buf[0..self.name_len];
    }

    pub fn setName(self: *ProcessEvent, units: []const u16) void {
        const n = @min(units.len, max_image_name_units);
        @memcpy(self.name_buf[0..n], units[0..n]);
        self.name_len = @intCast(n);
    }

    /// Copy a NUL-terminated UTF-16LE byte buffer (a raw payload tail or a
    /// TDH property value, any alignment) into the record, stopping at the
    /// buffer end and at capacity — truncation is a display concern only.
    pub fn setNameFromUtf16leBytes(self: *ProcessEvent, bytes: []const u8) void {
        var n: usize = 0;
        while (2 * n + 1 < bytes.len and n < max_image_name_units) : (n += 1) {
            const unit = std.mem.readInt(u16, bytes[2 * n ..][0..2], .little);
            if (unit == 0) break;
            self.name_buf[n] = unit;
        }
        self.name_len = @intCast(n);
    }
};

/// Identity of one connection for cold-start reconciliation: events racing
/// the table snapshot dedupe on this key (spec issue #18 "Cold start").
/// The owner tables know UDP sockets by local endpoint only, so UDP keys zero
/// the remote side — events collapse to the table's granularity.
pub const ConnKey = struct {
    proto: Proto,
    family: Family,
    local_addr: [16]u8,
    remote_addr: [16]u8,
    local_port: u16,
    remote_port: u16,
};

pub fn connKey(ev: NetEvent) ConnKey {
    return .{
        .proto = ev.proto,
        .family = ev.family,
        .local_addr = ev.local_addr,
        .remote_addr = if (ev.proto == .udp) @splat(0) else ev.remote_addr,
        .local_port = ev.local_port,
        .remote_port = if (ev.proto == .udp) 0 else ev.remote_port,
    };
}

fn testEvent(proto: Proto) NetEvent {
    return .{
        .op = .send,
        .proto = proto,
        .family = .v4,
        .pid = 1234,
        .size = 100,
        .local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0)),
        .remote_addr = [4]u8{ 93, 184, 216, 34 } ++ @as([12]u8, @splat(0)),
        .local_port = 51000,
        .remote_port = 443,
        .timestamp_ft = 0,
    };
}

test "TCP conn key carries the full normalized 5-tuple" {
    const key = connKey(testEvent(.tcp));
    try std.testing.expectEqual(Proto.tcp, key.proto);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 93, 184, 216, 34 }, key.remote_addr[0..4]);
    try std.testing.expectEqual(@as(u16, 443), key.remote_port);
    try std.testing.expectEqual(@as(u16, 51000), key.local_port);
}

test "UDP conn key zeroes the remote side to match table granularity" {
    const key = connKey(testEvent(.udp));
    try std.testing.expectEqual(Proto.udp, key.proto);
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &key.remote_addr);
    try std.testing.expectEqual(@as(u16, 0), key.remote_port);
    try std.testing.expectEqual(@as(u16, 51000), key.local_port);
}
