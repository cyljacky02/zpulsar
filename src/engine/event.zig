//! The fixed-size record the ETW consumer thread parses events into and
//! pushes onto the SPSC ring (spec issue #18 "Architecture and threading";
//! ADR-0002). One shared normalization for both event payloads and IP Helper
//! table rows: addresses stay raw network-order bytes, ports are converted to
//! host order once, at parse time.

const std = @import("std");

pub const Proto = enum(u8) { tcp, udp, icmp };
pub const Family = enum(u8) { v4, v6 };

/// What the Engine does with the record: send/recv accumulate In-session
/// Totals; connect/disconnect maintain the connection list. Events excluded
/// from totals (retransmit, protocol copy) never become records at all.
/// ICMP uses send/recv only — it has no lifecycle events.
pub const Op = enum(u8) { send, recv, connect, disconnect };

pub const NetEvent = struct {
    op: Op,
    proto: Proto,
    family: Family,
    /// ICMP only: the message's type number, which decides which outbound
    /// request an inbound reply pairs with (flows.zig). Zero otherwise —
    /// stated explicitly like every other field, so a new parser cannot
    /// forget it exists.
    icmp_type: u8,
    pid: u32,
    /// Bytes of the transport operation; 0 for lifecycle events, and always
    /// 0 for ICMP — no user-mode source reports ICMP message sizes
    /// (docs/research/icmp-visibility.md §Verdict), so ICMP Flows count
    /// messages instead and contribute nothing to any byte total.
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

/// One address as the name tiers key it: family plus raw network-order bytes,
/// v4 in the first 4.
pub const IpAddr = struct {
    family: Family,
    addr: [16]u8,

    /// The canonical form for name keying: an IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) is the v4 address it stands for.
    ///
    /// Both sides can produce the mapped form — the resolver reports a
    /// dual-family lookup's v4 answers that way
    /// (docs/research/dns-client-etw.md §4), and a dual-stack socket's
    /// Kernel-Network v6 events carry it too — so both normalize through here
    /// or a Flow could never match its own observation. Flow *identity* is
    /// untouched: this is the naming key, not the Flow key.
    pub fn normalized(self: IpAddr) IpAddr {
        if (self.family != .v6) return self;
        if (!std.mem.allEqual(u8, self.addr[0..10], 0)) return self;
        if (self.addr[10] != 0xff or self.addr[11] != 0xff) return self;
        var mapped: [16]u8 = @splat(0);
        @memcpy(mapped[0..4], self.addr[12..16]);
        return .{ .family = .v4, .addr = mapped };
    }
};

/// Longest hostname kept: the DNS wire limit is 253 characters (RFC 1035
/// §2.3.4). Longer names truncate — a display concern only; nothing keys on
/// the name.
pub const max_hostname_bytes = 256;

/// Addresses kept from one completed resolution. CDN answers routinely carry
/// several; beyond this the tail is dropped, costing only the names of flows
/// to the least-preferred answers.
pub const max_dns_addresses = 8;

/// Fixed-size Microsoft-Windows-DNS-Client 3008 record for the DNS ring
/// (docs/research/dns-client-etw.md §5): one completed resolution — the name
/// the process asked for, the CNAME chain's tail, and the addresses it
/// resolved to. Names are UTF-8: the payload's UTF-16 is converted at parse
/// time, on the consumer thread, without allocating.
pub const DnsEvent = struct {
    /// The querying process, from EVENT_HEADER.ProcessId — 3008 is emitted
    /// in-process and has no PID payload field (research §2).
    pid: u32,
    name_len: u16,
    alias_len: u16,
    addr_count: u8,
    name_buf: [max_hostname_bytes]u8,
    /// The CNAME chain's tail — the name the addresses actually belong to,
    /// kept for optional display. Empty when the answer had no CNAME.
    alias_buf: [max_hostname_bytes]u8,
    addrs: [max_dns_addresses]IpAddr,

    pub fn name(self: *const DnsEvent) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn alias(self: *const DnsEvent) []const u8 {
        return self.alias_buf[0..self.alias_len];
    }

    pub fn addresses(self: *const DnsEvent) []const IpAddr {
        return self.addrs[0..self.addr_count];
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
        .icmp_type = 0,
        .pid = 1234,
        .size = 100,
        .local_addr = [4]u8{ 192, 168, 1, 2 } ++ @as([12]u8, @splat(0)),
        .remote_addr = [4]u8{ 93, 184, 216, 34 } ++ @as([12]u8, @splat(0)),
        .local_port = 51000,
        .remote_port = 443,
        .timestamp_ft = 0,
    };
}

test "an IPv4-mapped IPv6 address keys as the v4 address it stands for" {
    const mapped: IpAddr = .{ .family = .v6, .addr = [12]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
    } ++ [4]u8{ 104, 20, 23, 154 } };
    const expected: IpAddr = .{
        .family = .v4,
        .addr = [4]u8{ 104, 20, 23, 154 } ++ @as([12]u8, @splat(0)),
    };
    try std.testing.expectEqual(expected, mapped.normalized());
    // Idempotent, and a real v6 address is left exactly as it is.
    try std.testing.expectEqual(expected, expected.normalized());
    const real_v6: IpAddr = .{ .family = .v6, .addr = [16]u8{
        0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x68, 0x10, 0x85, 0xe5,
    } };
    try std.testing.expectEqual(real_v6, real_v6.normalized());
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
