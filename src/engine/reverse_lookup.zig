//! The reverse-lookup lane (ADR-0002 thread 5; issue #26): `GetNameInfoW`
//! and nothing else, on its own thread behind a bounded queue.
//!
//! What it covers is the documented gap in DNS observation: processes that
//! carry their own resolver stub and never touch the Windows one emit no 3008
//! at all — verified for `nslookup`, documented for in-app DoH (research §7).
//! Their Flows miss every tier, and this lane is what keeps them from showing
//! nothing at all.
//!
//! It gets a thread because the address→name direction has no asynchronous
//! form — `GetNameInfoW` is synchronous only (§7) — so a PTR lookup against a
//! dead resolver blocks for seconds. Isolating it keeps that from starving the
//! Engine or the metadata lane, and keeps the Attribution Latency budget a
//! property of the hot path alone.
//!
//! What comes back is a *hint*, not an observation: Microsoft's own guidance
//! is that reverse lookups are "inherently unreliable, and should be used only
//! as a hint", and `ec2-52-1-2-3.compute-1.amazonaws.com` is plainly not the
//! name a process resolved. Results therefore land in the hint tier and
//! render dimmed. An address with no PTR record answers `no_record`, which the
//! Engine turns into a negative-cache entry — kept distinct from a lookup that
//! merely failed, which says nothing about the address and is not cached.
//!
//! Two rings and no locks, exactly like the ETW consumer's: the Engine pushes
//! requests and pops results, the lane does the reverse. Results are polled on
//! the Engine's flush tick rather than signalled — a reverse name arrives
//! seconds late by nature, so a tick of latency is free, and it keeps the lane
//! from ever touching a handle the Engine owns. That matters at shutdown: a
//! lane still stuck inside `GetNameInfoW` after the join timeout is abandoned
//! with its memory deliberately leaked (ADR-0002), and an abandoned thread
//! must not be able to reach anything still live.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");
const hostnames = @import("hostnames.zig");
const spsc_ring = @import("spsc_ring.zig");
const sync = @import("sync.zig");

/// What one blocking lookup produced. The distinction between the last two
/// matters: "this address has no PTR record" is evidence worth caching for ten
/// minutes, while "the lookup did not complete" is evidence about the
/// resolver, not the address, and caching it would blind the Engine to a whole
/// range of addresses because the network blipped.
pub const Answer = union(enum) {
    /// A PTR name of this many bytes, written to the caller's buffer.
    named: u16,
    /// `WSAHOST_NOT_FOUND` and friends: the address provably has no name.
    no_record,
    /// The lookup could not be completed at all.
    failed,
};

/// One finished lookup, as the Engine reads it.
pub const Result = struct {
    ip: event.IpAddr,
    answer: Answer,
    name_buf: [event.max_hostname_bytes]u8,

    pub fn name(self: *const Result) []const u8 {
        return switch (self.answer) {
            .named => |len| self.name_buf[0..len],
            .no_record, .failed => "",
        };
    }
};

pub const request_capacity = 512;
pub const result_capacity = 512;

pub const RequestRing = spsc_ring.SpscRing(event.IpAddr, request_capacity);
pub const ResultRing = spsc_ring.SpscRing(Result, result_capacity);

comptime {
    // The Engine never has more than `max_pending` addresses in flight, so
    // neither ring can fill. That is load-bearing, not incidental: a dropped
    // result would strand its address in the in-flight set, and the address
    // would never be looked up or shown again.
    std.debug.assert(request_capacity >= hostnames.max_pending);
    std.debug.assert(result_capacity >= hostnames.max_pending);
}

/// ADR-0002: shutdown abandons a stuck resolver thread after this long.
pub const stop_timeout_ms: u32 = 2000;

/// The blocking lookup itself — `GetNameInfoW` in production, a fake in
/// tests. Writes any name it finds into `out` as UTF-8.
pub const LookupFn = *const fn (ip: event.IpAddr, out: *[event.max_hostname_bytes]u8) Answer;

pub const StopResult = enum {
    /// The thread finished and was joined; the Lane can be freed.
    joined,
    /// Still inside a lookup after the timeout. The Lane (and its handles)
    /// must be leaked — the process is on its way out (ADR-0002).
    abandoned,
};

/// The rings make this ~90 KB — heap-allocate it; its address must be stable
/// for the lane thread.
pub const Lane = struct {
    requests: RequestRing = .{},
    results: ResultRing = .{},
    lookup: LookupFn = &win32Lookup,
    /// Set by the Engine when a request lands, and by `stop` to break the wait.
    wake: sync.WakeEvent,
    /// Set by the lane thread as its last act, so `stop` can bound its wait
    /// without polling.
    finished: sync.WakeEvent,
    stop_requested: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn init() error{EventCreateFailed}!Lane {
        const wake = try sync.WakeEvent.init();
        errdefer wake.deinit();
        return .{ .wake = wake, .finished = try sync.WakeEvent.init() };
    }

    /// Only ever called on a Lane whose thread is joined (or never started) —
    /// an abandoned Lane is leaked whole, handles included.
    pub fn deinit(self: *Lane) void {
        self.wake.deinit();
        self.finished.deinit();
    }

    /// Winsock init happens here, before the thread exists, so its failure is
    /// a failure to start rather than a lane that silently answers "no record"
    /// to everything and negative-caches the whole address space.
    pub fn start(self: *Lane) error{ SpawnFailed, WinsockUnavailable }!void {
        if (!win32.wsaStartup()) return error.WinsockUnavailable;
        self.thread = std.Thread.spawn(.{}, run, .{self}) catch return error.SpawnFailed;
    }

    pub fn stop(self: *Lane) StopResult {
        const thread = self.thread orelse return .joined;
        self.stop_requested.store(true, .release);
        self.wake.set();
        // A lookup already in flight cannot be cancelled; past the timeout the
        // thread is abandoned and the caller leaks this Lane (ADR-0002).
        if (self.finished.timedWait(stop_timeout_ms) == .timeout) return .abandoned;
        thread.join();
        self.thread = null;
        return .joined;
    }

    /// Engine side: queue an address. False when the queue is full — the
    /// caller must then release its in-flight claim on the address.
    pub fn request(self: *Lane, ip: event.IpAddr) bool {
        if (self.requests.push(ip) == .dropped) return false;
        self.wake.set();
        return true;
    }

    /// Engine side: drain one finished lookup.
    pub fn popResult(self: *Lane) ?Result {
        return self.results.pop();
    }

    /// Lane side, and the seam tests drive: resolve everything queued.
    pub fn serviceOnce(self: *Lane) void {
        while (self.requests.pop()) |ip| {
            var out: Result = .{ .ip = ip, .answer = .failed, .name_buf = undefined };
            out.answer = self.lookup(ip, &out.name_buf);
            // Sized so this cannot drop (see the comptime assert above).
            _ = self.results.push(out);
        }
    }

    fn run(self: *Lane) void {
        while (!self.stop_requested.load(.acquire)) {
            self.serviceOnce();
            // The wake is auto-reset, so a request that landed during the
            // drain is still holding a signal here — no lost wakeup.
            if (self.requests.isEmpty()) _ = self.wake.timedWait(win32.INFINITE);
        }
        self.finished.set();
    }
};

/// `GetNameInfoW` with `NI_NAMEREQD | NI_NUMERICSERV`: an address with no PTR
/// record fails with `WSAHOST_NOT_FOUND` instead of echoing the address back,
/// which is exactly what makes a negative result distinguishable from a
/// positive one (research §7).
fn win32Lookup(ip: event.IpAddr, out: *[event.max_hostname_bytes]u8) Answer {
    var host: [event.max_hostname_bytes]u16 = undefined;
    // One sockaddr buffer for both families: only the leading bytes differ,
    // and the length passed to GetNameInfoW is what selects between them.
    var sa = std.mem.zeroes(win32.SOCKADDR_IN6);
    const sa_len: i32 = switch (ip.family) {
        .v4 => blk: {
            const v4: *win32.SOCKADDR_IN = @ptrCast(&sa);
            v4.sin_family = win32.AF_INET_FAMILY;
            @memcpy(std.mem.asBytes(&v4.sin_addr)[0..4], ip.addr[0..4]);
            break :blk @sizeOf(win32.SOCKADDR_IN);
        },
        .v6 => blk: {
            sa.sin6_family = win32.AF_INET6_FAMILY;
            @memcpy(std.mem.asBytes(&sa.sin6_addr)[0..16], &ip.addr);
            break :blk @sizeOf(win32.SOCKADDR_IN6);
        },
    };
    const rc = win32.GetNameInfoW(
        @ptrCast(&sa),
        sa_len,
        &host,
        host.len,
        null,
        0,
        win32.NI_NAMEREQD | win32.NI_NUMERICSERV,
    );
    if (rc != 0) return switch (win32.wsaLastError()) {
        // Evidence about the address: it has no name, and saying so is worth
        // ten minutes of not asking again.
        win32.WSAHOST_NOT_FOUND, win32.WSANO_DATA, win32.WSANO_RECOVERY => .no_record,
        // Evidence about the resolver. Caching this would suppress lookups for
        // addresses that are perfectly resolvable once the network recovers.
        else => .failed,
    };

    // wtf16LeToWtf8 asserts its output fits, so convert into a worst-case
    // buffer; a name that then overruns the record is dropped rather than cut
    // mid-sequence — PTR names are ASCII, so this is a defensive path only.
    var utf8: [3 * event.max_hostname_bytes]u8 = undefined;
    const n = std.unicode.wtf16LeToWtf8(&utf8, std.mem.sliceTo(&host, 0));
    if (n == 0 or n > out.len) return .failed;
    @memcpy(out[0..n], utf8[0..n]);
    return .{ .named = @intCast(n) };
}

// ---------------------------------------------------------------------------
// Tests — the lane with its blocking call faked out, so the queueing,
// negative-result, and thread-lifecycle behavior is exercised without a
// resolver. The live GetNameInfoW path runs through the headless rig.
// ---------------------------------------------------------------------------

const test_name = "ec2-93-184-216-34.compute-1.test";

fn fakeFound(ip: event.IpAddr, out: *[event.max_hostname_bytes]u8) Answer {
    _ = ip;
    @memcpy(out[0..test_name.len], test_name);
    return .{ .named = test_name.len };
}

fn fakeMissing(ip: event.IpAddr, out: *[event.max_hostname_bytes]u8) Answer {
    _ = .{ ip, out };
    return .no_record;
}

fn fakeUnreachable(ip: event.IpAddr, out: *[event.max_hostname_bytes]u8) Answer {
    _ = .{ ip, out };
    return .failed;
}

fn ip4(bytes: [4]u8) event.IpAddr {
    var addr: [16]u8 = @splat(0);
    @memcpy(addr[0..4], &bytes);
    return .{ .family = .v4, .addr = addr };
}

const addr_a = ip4(.{ 93, 184, 216, 34 });

fn testLane(lookup: LookupFn) !*Lane {
    const lane = try std.testing.allocator.create(Lane);
    lane.* = try Lane.init();
    lane.lookup = lookup;
    return lane;
}

fn destroy(lane: *Lane) void {
    lane.deinit();
    std.testing.allocator.destroy(lane);
}

test "a queued address comes back as its PTR name" {
    const lane = try testLane(&fakeFound);
    defer destroy(lane);

    try std.testing.expect(lane.request(addr_a));
    try std.testing.expectEqual(@as(?Result, null), lane.popResult());

    lane.serviceOnce();
    const res = lane.popResult() orelse return error.ExpectedResult;
    try std.testing.expectEqual(addr_a, res.ip);
    try std.testing.expectEqualStrings(test_name, res.name());
}

test "an address with no PTR record comes back as a negative answer, not silence" {
    const lane = try testLane(&fakeMissing);
    defer destroy(lane);

    try std.testing.expect(lane.request(addr_a));
    lane.serviceOnce();

    // The negative answer must reach the Engine — it is what stops the
    // address being asked about again for the next ten minutes.
    const res = lane.popResult() orelse return error.ExpectedResult;
    try std.testing.expectEqual(addr_a, res.ip);
    try std.testing.expectEqual(Answer.no_record, res.answer);
    try std.testing.expectEqual(@as(usize, 0), res.name().len);
}

test "a lookup that could not complete is not reported as an absent name" {
    const lane = try testLane(&fakeUnreachable);
    defer destroy(lane);

    try std.testing.expect(lane.request(addr_a));
    lane.serviceOnce();

    // "The resolver is unreachable" says nothing about this address. Letting
    // it pass as `no_record` would negative-cache whole ranges over a blip.
    const res = lane.popResult() orelse return error.ExpectedResult;
    try std.testing.expectEqual(Answer.failed, res.answer);
}

test "one pass resolves everything queued" {
    const lane = try testLane(&fakeFound);
    defer destroy(lane);

    for (0..4) |i| try std.testing.expect(lane.request(ip4(.{ 10, 0, 0, @intCast(i) })));
    lane.serviceOnce();

    for (0..4) |i| {
        const res = lane.popResult() orelse return error.ExpectedResult;
        try std.testing.expectEqual(ip4(.{ 10, 0, 0, @intCast(i) }), res.ip);
    }
    try std.testing.expectEqual(@as(?Result, null), lane.popResult());
}

test "a full queue refuses the request instead of blocking the Engine" {
    const lane = try testLane(&fakeFound);
    defer destroy(lane);

    var accepted: usize = 0;
    while (lane.request(addr_a)) accepted += 1;
    try std.testing.expectEqual(request_capacity, accepted);
    // The Engine learns the address was not queued, so it can release its
    // in-flight claim rather than leave the address stuck forever.
    try std.testing.expect(!lane.request(addr_a));
}

test "the lane thread resolves and stops cleanly" {
    const lane = try testLane(&fakeFound);
    defer destroy(lane);

    try lane.start();
    try std.testing.expect(lane.request(addr_a));

    // The thread has no completion signal by design; the Engine polls.
    var waited: u32 = 0;
    const res = while (waited < stop_timeout_ms) : (waited += 5) {
        if (lane.popResult()) |r| break r;
        win32.Sleep(5);
    } else return error.LookupNeverCompleted;
    try std.testing.expectEqualStrings(test_name, res.name());

    try std.testing.expectEqual(StopResult.joined, lane.stop());
    // Stopping an already-stopped lane is harmless (shutdown paths overlap).
    try std.testing.expectEqual(StopResult.joined, lane.stop());
}
