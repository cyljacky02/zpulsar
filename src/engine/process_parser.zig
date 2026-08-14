//! Fixed-offset parsing of Microsoft-Windows-Kernel-Process payloads into
//! ProcessEvent records (docs/research/kernel-process-etw.md §Verdict).
//! Version-dispatched: the kernel emits exactly one version per build, and
//! fields were *inserted* between versions (not appended), so an unknown
//! version must never be parsed with these offsets — it routes to the TDH
//! fallback instead. Payloads are tightly packed; u64 loads at unaligned
//! offsets are legitimate.
//!
//! Implemented (id, version) pairs: {1v2, 1v3, 1v4, 2v1, 2v2, 15v0, 15v1,
//! 15v2}. Start and rundown share layouts per version pair (1v2≡15v0,
//! 1v3≡15v1, 1v4≡15v2). The stop-event ImageName is ANSI and
//! kernel-truncated — it is never read (research §2.4).

const std = @import("std");
const event = @import("event.zig");

/// Kernel-Process event ids under keyword 0x10 (provider manifest).
pub const Id = struct {
    pub const process_start: u16 = 1;
    pub const process_stop: u16 = 2;
    pub const process_rundown: u16 = 15;
};

pub const ParseResult = union(enum) {
    /// A record for the process ring.
    event: event.ProcessEvent,
    /// Not an event the Engine consumes: unknown id (e.g. 27
    /// ProcessInPrivateSet) or a malformed/truncated payload.
    drop,
    /// An id we consume at a version we have no layout for — the caller
    /// routes the record, as this kind, to the TDH fallback.
    unknown_version: event.ProcessKind,
};

pub fn parse(id: u16, version: u8, user_data: []const u8) ParseResult {
    return switch (id) {
        Id.process_start => switch (version) {
            2 => parseStartLike(.start, .fixed24, user_data),
            3, 4 => parseStartLike(.start, .sid_skip, user_data),
            else => .{ .unknown_version = .start },
        },
        Id.process_rundown => switch (version) {
            0 => parseStartLike(.rundown, .fixed24, user_data),
            1, 2 => parseStartLike(.rundown, .sid_skip, user_data),
            else => .{ .unknown_version = .rundown },
        },
        Id.process_stop => switch (version) {
            1 => parseStop(.{ .create_time = 4, .exit_time = 12 }, user_data),
            2 => parseStop(.{ .create_time = 12, .exit_time = 20 }, user_data),
            else => .{ .unknown_version = .stop },
        },
        else => .drop,
    };
}

/// Start/rundown layouts (research §Verdict): v2/15v0 have ImageName at a
/// fixed offset 24; v3+/15v1+ insert sequence numbers and token info, then a
/// variable-length MandatoryLabel SID at 48 that must be skipped by computed
/// length before the name.
const StartLayout = enum { fixed24, sid_skip };

fn parseStartLike(
    kind: event.ProcessKind,
    layout: StartLayout,
    user_data: []const u8,
) ParseResult {
    var out: event.ProcessEvent = .{
        .kind = kind,
        .pid = undefined,
        .create_time = undefined,
        .exit_time = 0,
        .name_len = 0,
        .name_buf = undefined,
    };
    const name_off: usize = switch (layout) {
        .fixed24 => blk: {
            if (user_data.len < 24) return .drop;
            out.pid = std.mem.readInt(u32, user_data[0..4], .little);
            out.create_time = std.mem.readInt(u64, user_data[4..12], .little);
            break :blk 24;
        },
        .sid_skip => blk: {
            // Fixed prefix through the SID's SubAuthorityCount byte at 49.
            if (user_data.len < 50) return .drop;
            out.pid = std.mem.readInt(u32, user_data[0..4], .little);
            out.create_time = std.mem.readInt(u64, user_data[12..20], .little);
            // Raw SID: Revision u8, SubAuthorityCount u8, authority u8[6],
            // SubAuthority u32×count — length 8 + 4×count (research §2.2).
            const sub_auths = user_data[49];
            if (sub_auths > 15) return .drop; // SID_MAX_SUB_AUTHORITIES
            break :blk 48 + 8 + 4 * @as(usize, sub_auths);
        },
    };
    if (user_data.len < name_off) return .drop;
    // The NUL-terminated UTF-16LE ImageName; a payload cut short of the NUL
    // yields the readable prefix (defensive — the manifest guarantees it).
    out.setNameFromUtf16leBytes(user_data[name_off..]);
    return .{ .event = out };
}

const StopOffsets = struct { create_time: usize, exit_time: usize };

fn parseStop(comptime off: StopOffsets, user_data: []const u8) ParseResult {
    if (user_data.len < off.exit_time + 8) return .drop;
    return .{ .event = .{
        .kind = .stop,
        .pid = std.mem.readInt(u32, user_data[0..4], .little),
        .create_time = std.mem.readInt(u64, user_data[off.create_time..][0..8], .little),
        .exit_time = std.mem.readInt(u64, user_data[off.exit_time..][0..8], .little),
        // The trailing ANSI ImageName is deliberately never read.
        .name_len = 0,
        .name_buf = undefined,
    } };
}

// ---------------------------------------------------------------------------
// Fixtures — every (id, version) pair the engine claims to parse, built
// field-by-field in the manifest's declaration order (spec issue #18, Testing
// Decisions). The builders ARE the layout: change an offset and the payload
// bytes change with it.
// ---------------------------------------------------------------------------

fn le32(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    return b;
}

fn le64(v: u64) [8]u8 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    return b;
}

/// ASCII → NUL-terminated UTF-16LE payload bytes.
fn wsz(comptime ascii: []const u8) [2 * ascii.len + 2]u8 {
    var b: [2 * ascii.len + 2]u8 = @splat(0);
    for (ascii, 0..) |c, i| b[2 * i] = c;
    return b;
}

const test_pid: u32 = 45556;
/// Real CreateTime FILETIME from the research doc's captured PING.EXE start.
const test_create: u64 = 0x01DD2BF51EDBC0A1;
const test_exit: u64 = 0x01DD2BF530000000;
const test_name = "\\Device\\HarddiskVolume3\\Windows\\System32\\PING.EXE";

/// S-1-16-12288 mandatory label — the 12-byte SID every local capture showed.
const sid_s1_16 = [12]u8{ 1, 1, 0, 0, 0, 0, 0, 0x10, 0, 0x30, 0, 0 };
/// A 2-sub-authority SID (16 bytes): the skip must be computed, not
/// hardcoded to 12.
const sid_two_subs = [8]u8{ 1, 2, 0, 0, 0, 0, 0, 5 } ++ le32(32) ++ le32(544);

/// Trailer after ImageName in every start/rundown version: ImageChecksum,
/// TimeDateStamp, two empty package strings.
const start_trailer = le32(0xC0FFEE) ++ le32(0x66aa77bb) ++ [2]u8{ 0, 0 } ++ [2]u8{ 0, 0 };

/// v2 / 15v0 (1703–1809): PID, CreateTime, ParentPID, SessionID, Flags,
/// ImageName, trailer. Call at comptime only — the result references the
/// comptime-materialized array (a runtime call would return a pointer to a
/// dead stack temporary).
fn startV2Payload(comptime name: []const u8) []const u8 {
    return &(le32(test_pid) ++ le64(test_create) ++ le32(47284) ++ le32(1) ++
        le32(0) ++ wsz(name) ++ start_trailer);
}

/// v3 / 15v1 (1903+): PID, SequenceNumber, CreateTime, ParentPID,
/// ParentSequenceNumber, SessionID, Flags, TokenElevationType,
/// TokenIsElevated, MandatoryLabel SID, ImageName, trailer.
fn startV3Payload(comptime sid: []const u8, comptime name: []const u8) []const u8 {
    return &(le32(test_pid) ++ le64(1518780) ++ le64(test_create) ++ le32(47284) ++
        le64(1518000) ++ le32(1) ++ le32(0) ++ le32(1) ++ le32(0) ++
        sid[0..sid.len].* ++ wsz(name) ++ start_trailer);
}

/// v4 / 15v2 (24H2+): v3 plus trailing SecurityMitigations u32.
fn startV4Payload(comptime sid: []const u8, comptime name: []const u8) []const u8 {
    const v3 = startV3Payload(sid, name);
    return &(v3[0..v3.len].* ++ le32(0x21));
}

// Comptime-materialized payloads for the runtime tests below.
const start_v2_payload = startV2Payload(test_name);
const start_v3_payload = startV3Payload(&sid_s1_16, test_name);

/// Stop v1 (1703–1809): PID, CreateTime, ExitTime, ExitCode,
/// TokenElevationType, HandleCount, CommitCharge, CommitPeak, CPUCycleCount,
/// ReadOps, WriteOps, ReadKB, WriteKB, HardFaultCount, ANSI ImageName
/// (kernel-truncated — the parser must never read it).
const stop_v1_payload = le32(test_pid) ++ le64(test_create) ++ le64(test_exit) ++
    le32(0) ++ le32(1) ++ le32(51) ++ le64(4096) ++ le64(8192) ++ le64(123456) ++
    le32(10) ++ le32(11) ++ le32(12) ++ le32(13) ++ le32(2) ++ "zp_longname_pr\x00".*;

/// Stop v2 (1903+): SequenceNumber inserted at 4 — every later field +8.
const stop_v2_payload = le32(test_pid) ++ le64(1518780) ++ le64(test_create) ++
    le64(test_exit) ++ le32(0) ++ le32(1) ++ le32(51) ++ le64(4096) ++ le64(8192) ++
    le64(123456) ++ le32(10) ++ le32(11) ++ le32(12) ++ le32(13) ++ le32(2) ++
    "zp_longname_pr\x00".*;

const Expect = struct {
    kind: event.ProcessKind,
    exit_time: u64 = 0,
    name: []const u8 = "",
};

const Fixture = struct {
    name: []const u8,
    id: u16,
    version: u8,
    payload: []const u8,
    expect: Expect,
};

const fixtures = [_]Fixture{
    .{ .name = "1v2 start (1809)", .id = 1, .version = 2, .payload = startV2Payload(test_name), .expect = .{ .kind = .start, .name = test_name } },
    .{ .name = "1v3 start (1903+)", .id = 1, .version = 3, .payload = startV3Payload(&sid_s1_16, test_name), .expect = .{ .kind = .start, .name = test_name } },
    .{ .name = "1v4 start (24H2+)", .id = 1, .version = 4, .payload = startV4Payload(&sid_s1_16, test_name), .expect = .{ .kind = .start, .name = test_name } },
    .{ .name = "15v0 rundown (1809)", .id = 15, .version = 0, .payload = startV2Payload(test_name), .expect = .{ .kind = .rundown, .name = test_name } },
    .{ .name = "15v1 rundown (1903+)", .id = 15, .version = 1, .payload = startV3Payload(&sid_s1_16, test_name), .expect = .{ .kind = .rundown, .name = test_name } },
    .{ .name = "15v2 rundown (24H2+)", .id = 15, .version = 2, .payload = startV4Payload(&sid_s1_16, test_name), .expect = .{ .kind = .rundown, .name = test_name } },
    .{ .name = "2v1 stop (1809)", .id = 2, .version = 1, .payload = &stop_v1_payload, .expect = .{ .kind = .stop, .exit_time = test_exit } },
    .{ .name = "2v2 stop (1903+)", .id = 2, .version = 2, .payload = &stop_v2_payload, .expect = .{ .kind = .stop, .exit_time = test_exit } },
    // Kernel/minimal processes carry a bare name with no path (research §2.3).
    .{ .name = "15v1 bare-name minimal process", .id = 15, .version = 1, .payload = startV3Payload(&sid_s1_16, "MemCompression"), .expect = .{ .kind = .rundown, .name = "MemCompression" } },
    // The SID skip is computed from SubAuthorityCount, never hardcoded.
    .{ .name = "1v3 with a 16-byte SID", .id = 1, .version = 3, .payload = startV3Payload(&sid_two_subs, test_name), .expect = .{ .kind = .start, .name = test_name } },
};

fn expectName(expected_ascii: []const u8, ev: event.ProcessEvent) !void {
    try std.testing.expectEqual(expected_ascii.len, ev.name().len);
    for (expected_ascii, ev.name()) |c, unit| {
        try std.testing.expectEqual(@as(u16, c), unit);
    }
}

test "fixtures: every implemented (id, version) pair parses to its record" {
    for (fixtures) |f| {
        errdefer std.debug.print("fixture failed: {s}\n", .{f.name});
        const ev = switch (parse(f.id, f.version, f.payload)) {
            .event => |ev| ev,
            else => return error.ExpectedRecord,
        };
        try std.testing.expectEqual(f.expect.kind, ev.kind);
        try std.testing.expectEqual(test_pid, ev.pid);
        // The row key is the raw payload FILETIME, bit-exact.
        try std.testing.expectEqual(test_create, ev.create_time);
        try std.testing.expectEqual(f.expect.exit_time, ev.exit_time);
        try expectName(f.expect.name, ev);
    }
}

test "the truncated stop-event name is never read" {
    // Both stop payloads end in ANSI name bytes; the record must ignore them.
    for ([_]struct { v: u8, p: []const u8 }{
        .{ .v = 1, .p = &stop_v1_payload },
        .{ .v = 2, .p = &stop_v2_payload },
    }) |case| {
        const ev = parse(2, case.v, case.p).event;
        try std.testing.expectEqual(@as(u16, 0), ev.name_len);
    }
}

test "unknown versions route to the TDH fallback, never to old offsets" {
    const cases = [_]struct { id: u16, version: u8, kind: event.ProcessKind }{
        .{ .id = 1, .version = 5, .kind = .start }, // future
        .{ .id = 2, .version = 3, .kind = .stop },
        .{ .id = 15, .version = 3, .kind = .rundown },
        // Pre-1703, unreachable on 1809+ but honest.
        .{ .id = 1, .version = 1, .kind = .start },
        .{ .id = 2, .version = 0, .kind = .stop },
    };
    for (cases) |c| {
        try std.testing.expectEqual(
            ParseResult{ .unknown_version = c.kind },
            parse(c.id, c.version, start_v2_payload),
        );
    }
}

test "unknown ids drop: 27 ProcessInPrivateSet shares the keyword" {
    try std.testing.expectEqual(ParseResult.drop, parse(27, 0, start_v2_payload));
    try std.testing.expectEqual(ParseResult.drop, parse(999, 2, start_v2_payload));
}

test "truncated payloads drop" {
    const v2 = start_v2_payload;
    const v3 = start_v3_payload;
    // One byte short of each layout's fixed prefix.
    try std.testing.expectEqual(ParseResult.drop, parse(1, 2, v2[0..23]));
    try std.testing.expectEqual(ParseResult.drop, parse(1, 3, v3[0..49]));
    // Payload ends inside the SID: the computed name offset is out of range.
    try std.testing.expectEqual(ParseResult.drop, parse(1, 3, v3[0..55]));
    try std.testing.expectEqual(ParseResult.drop, parse(2, 1, stop_v1_payload[0..19]));
    try std.testing.expectEqual(ParseResult.drop, parse(2, 2, stop_v2_payload[0..27]));
    try std.testing.expectEqual(ParseResult.drop, parse(15, 0, &.{}));
    // Exactly the read prefix still parses; the name is just absent.
    const ev = parse(1, 2, v2[0..24]).event;
    try std.testing.expectEqual(@as(u16, 0), ev.name_len);
    try std.testing.expectEqual(test_create, ev.create_time);
}

test "a corrupt SID sub-authority count drops instead of a wild name offset" {
    var bad: [256]u8 = undefined;
    @memcpy(bad[0..start_v3_payload.len], start_v3_payload);
    bad[49] = 16; // > SID_MAX_SUB_AUTHORITIES
    try std.testing.expectEqual(ParseResult.drop, parse(1, 3, bad[0..start_v3_payload.len]));
}

test "names longer than the record capacity truncate cleanly" {
    const long_name = "\\Device\\HarddiskVolume3\\" ++ "a" ** 400;
    const payload = comptime startV2Payload(long_name);
    const ev = parse(1, 2, payload).event;
    try std.testing.expectEqual(@as(usize, event.max_image_name_units), ev.name().len);
    try expectName(long_name[0..event.max_image_name_units], ev);
}
