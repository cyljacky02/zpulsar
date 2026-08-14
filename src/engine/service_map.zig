//! Tier 1 of Service Attribution (issue #25; spec issue #18 "Attribution:
//! services inside shared hosts"; docs/research/svchost-service-attribution.md
//! §1 and §4): the PID → hosted-services map, enumerated from the SCM.
//!
//! Since Windows 10 1703 the SCM splits services into one host process each
//! on client SKUs with more than 3.5 GB RAM, so on virtually every machine
//! zPulsar targets most svchost PIDs host exactly one service and this map is
//! the whole answer — no per-socket call needed. It is also what makes the
//! tier 3 fallback honest: when per-socket resolution fails, the label carries
//! the *actual* hosted-service list, never a guessed single service.
//!
//! PIDs are reused, so a map is only allowed to describe processes that
//! already existed when it was captured — hence `captured_ft`, sampled
//! immediately before the enumeration. Comparing it against a Process Row's
//! payload CreateTime gives the (PID, process start time) key the research
//! calls for, without opening a handle per service PID.

const std = @import("std");
const win32 = @import("win32");

/// One hosted service: which process runs it, and its SCM key name (the name
/// `GetOwnerModuleFrom*Entry` can return, not the display name).
pub const Pair = struct {
    pid: u32,
    name: []const u8,
};

/// One SCM enumeration, owned by whoever holds it. Produced on the metadata
/// resolver lane and handed to the Engine thread, which interns the names and
/// frees this — so it is deliberately self-contained and thread-agnostic.
pub const Raw = struct {
    /// Wall clock (FILETIME) sampled immediately *before* the enumeration: a
    /// process created at or after this instant cannot be described here.
    captured_ft: u64,
    entries: []Pair,
    /// One block backing every `entries[i].name`.
    names: []u8,

    pub fn deinit(self: *Raw, gpa: std.mem.Allocator) void {
        gpa.free(self.names);
        gpa.free(self.entries);
        gpa.destroy(self);
    }
};

/// Copy `pairs` into a self-contained Raw. The single production path and the
/// seam tests drive the Engine through.
pub fn fromPairs(
    gpa: std.mem.Allocator,
    captured_ft: u64,
    pairs: []const Pair,
) error{OutOfMemory}!*Raw {
    var total: usize = 0;
    for (pairs) |p| total += p.name.len;

    const names = try gpa.alloc(u8, total);
    errdefer gpa.free(names);
    const entries = try gpa.alloc(Pair, pairs.len);
    errdefer gpa.free(entries);

    var off: usize = 0;
    for (pairs, entries) |src, *dst| {
        @memcpy(names[off..][0..src.name.len], src.name);
        dst.* = .{ .pid = src.pid, .name = names[off..][0..src.name.len] };
        off += src.name.len;
    }

    const raw = try gpa.create(Raw);
    raw.* = .{ .captured_ft = captured_ft, .entries = entries, .names = names };
    return raw;
}

/// Order for the by-PID grouping the Engine does at install time. Names sort
/// within a PID so a shared host's service list has a stable display order.
pub fn pairLessThan(_: void, a: Pair, b: Pair) bool {
    if (a.pid != b.pid) return a.pid < b.pid;
    return std.mem.lessThan(u8, a.name, b.name);
}

/// The services `pid` hosts, as a sub-slice of `sorted` (which must be sorted
/// by `pairLessThan`). Empty when the PID hosts none.
pub fn servicesFor(sorted: []const Pair, pid: u32) []const Pair {
    var lo: usize = 0;
    var hi: usize = sorted.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (sorted[mid].pid < pid) lo = mid + 1 else hi = mid;
    }
    var end = lo;
    while (end < sorted.len and sorted[end].pid == pid) end += 1;
    return sorted[lo..end];
}

/// The SCM enumeration itself — a blocking control-path call, so it only ever
/// runs on the metadata resolver lane. Null on any failure; the Engine simply
/// keeps the map it has (or none), and every affected Flow stays on the
/// honest fallback.
///
/// `SC_MANAGER_ENUMERATE_SERVICE` is all `EnumServicesStatusEx` documents as
/// required; services the caller cannot query are silently omitted, which is a
/// non-issue elevated (research §4).
pub fn query(gpa: std.mem.Allocator) ?*Raw {
    const scm = win32.OpenSCManagerW(
        null,
        null,
        win32.SC_MANAGER_CONNECT | win32.SC_MANAGER_ENUMERATE_SERVICE,
    );
    if (scm == win32.NULL_SC_HANDLE) return null;
    defer _ = win32.CloseServiceHandle(scm);

    // Sampled before the first call: everything the enumeration reports
    // existed at or before this instant.
    const captured_ft = win32.systemTimeAsFileTime();

    var names: std.ArrayList(u8) = .empty;
    defer names.deinit(gpa);
    var slots: std.ArrayList(Slot) = .empty;
    defer slots.deinit(gpa);

    var buf: []align(8) u8 = &.{};
    defer if (buf.len != 0) gpa.free(buf);
    var resume_handle: u32 = 0;
    // ERROR_MORE_DATA resumes rather than restarts, so the loop terminates on
    // its own; the cap is a backstop against an SCM that never makes progress.
    var rounds: u8 = 0;
    while (rounds < 32) : (rounds += 1) {
        var needed: u32 = 0;
        var returned: u32 = 0;
        const ok = win32.EnumServicesStatusExW(
            scm,
            win32.SC_ENUM_PROCESS_INFO,
            win32.SERVICE_WIN32,
            win32.SERVICE_ACTIVE,
            if (buf.len == 0) null else @ptrCast(buf.ptr),
            @intCast(buf.len),
            &needed,
            &returned,
            &resume_handle,
            null,
        );
        const more = ok == win32.FALSE and win32.GetLastError() == win32.ERROR_MORE_DATA;
        if (ok == win32.FALSE and !more) return null;

        collect(gpa, buf, returned, &names, &slots) catch return null;
        if (!more) break;
        // Buffer too small for even one more entry: grow to what the SCM
        // asked for. Otherwise the partial round made progress — go again.
        if (returned == 0) {
            if (needed == 0) return null;
            if (buf.len != 0) gpa.free(buf);
            buf = gpa.alignedAlloc(u8, .of(u64), needed) catch {
                buf = &.{};
                return null;
            };
        }
    } else return null;

    const pairs = gpa.alloc(Pair, slots.items.len) catch return null;
    defer gpa.free(pairs);
    for (slots.items, pairs) |s, *p| p.* = .{ .pid = s.pid, .name = names.items[s.off..][0..s.len] };
    return fromPairs(gpa, captured_ft, pairs) catch null;
}

/// A name's place in the growing `names` buffer — recorded as an offset
/// because appending may move it.
const Slot = struct {
    pid: u32,
    off: u32,
    len: u32,
};

/// Append the round's entries. Services with no PID are not running in any
/// process we could attribute a socket to, so they are skipped.
fn collect(
    gpa: std.mem.Allocator,
    buf: []align(8) const u8,
    returned: u32,
    names: *std.ArrayList(u8),
    slots: *std.ArrayList(Slot),
) error{OutOfMemory}!void {
    const Entry = win32.ENUM_SERVICE_STATUS_PROCESSW;
    if (returned == 0 or buf.len / @sizeOf(Entry) < returned) return;
    const list = @as([*]const Entry, @ptrCast(@alignCast(buf.ptr)))[0..returned];
    for (list) |e| {
        const pid = e.ServiceStatusProcess.dwProcessId;
        if (pid == 0) continue;
        const name_ptr = e.lpServiceName orelse continue;
        const units = std.mem.sliceTo(name_ptr, 0);
        const off = names.items.len;
        try names.ensureUnusedCapacity(gpa, 3 * units.len);
        names.items.len += std.unicode.wtf16LeToWtf8(names.unusedCapacitySlice(), units);
        try slots.append(gpa, .{
            .pid = pid,
            .off = @intCast(off),
            .len = @intCast(names.items.len - off),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests — the pure grouping the Engine installs through; the live SCM
// enumeration needs a real machine and is exercised by the headless rig.
// ---------------------------------------------------------------------------

test "a Raw owns its names independently of the pairs it was built from" {
    const gpa = std.testing.allocator;
    var scratch = [_]u8{ 'R', 'p', 'c', 'S', 's' };
    const raw = try fromPairs(gpa, 500, &.{.{ .pid = 900, .name = &scratch }});
    defer raw.deinit(gpa);

    @memset(&scratch, 'x'); // the source is gone; the Raw's copy is not
    try std.testing.expectEqual(@as(u64, 500), raw.captured_ft);
    try std.testing.expectEqualStrings("RpcSs", raw.entries[0].name);
}

test "sorted pairs group into per-PID service lists" {
    const gpa = std.testing.allocator;
    // A deliberately grouped host (the RPC pair), a single-service host, and
    // a service whose PID sorts between them.
    const raw = try fromPairs(gpa, 500, &.{
        .{ .pid = 900, .name = "RpcSs" },
        .{ .pid = 700, .name = "Dnscache" },
        .{ .pid = 900, .name = "RpcEptMapper" },
    });
    defer raw.deinit(gpa);
    std.mem.sort(Pair, raw.entries, {}, pairLessThan);

    const shared = servicesFor(raw.entries, 900);
    try std.testing.expectEqual(@as(usize, 2), shared.len);
    // Sorted within the PID, so the display list never reshuffles.
    try std.testing.expectEqualStrings("RpcEptMapper", shared[0].name);
    try std.testing.expectEqualStrings("RpcSs", shared[1].name);

    const single = servicesFor(raw.entries, 700);
    try std.testing.expectEqual(@as(usize, 1), single.len);
    try std.testing.expectEqualStrings("Dnscache", single[0].name);

    // A PID that hosts nothing — and one past either end of the table.
    try std.testing.expectEqual(@as(usize, 0), servicesFor(raw.entries, 800).len);
    try std.testing.expectEqual(@as(usize, 0), servicesFor(raw.entries, 1).len);
    try std.testing.expectEqual(@as(usize, 0), servicesFor(raw.entries, 99999).len);
    try std.testing.expectEqual(@as(usize, 0), servicesFor(&.{}, 900).len);
}
