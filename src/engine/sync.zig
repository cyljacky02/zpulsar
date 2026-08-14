//! Engine-side wrappers over Win32 synchronization. The wake events of
//! ADR-0002 (ring empty→non-empty, Snapshot published) are real auto-reset
//! event HANDLEs so the app layer can MsgWaitForMultipleObjects on them
//! later; the Snapshot slot's lock is an SRWLOCK — never taken on the
//! per-event hot path.

const std = @import("std");
const win32 = @import("win32");

/// Auto-reset Win32 event: one successful wait consumes the signal; setting
/// an already-set event stays a single signal.
pub const WakeEvent = struct {
    handle: win32.HANDLE,

    pub fn init() error{EventCreateFailed}!WakeEvent {
        const h = win32.CreateEventW(null, win32.FALSE, win32.FALSE, null) orelse
            return error.EventCreateFailed;
        return .{ .handle = h };
    }

    pub fn deinit(self: WakeEvent) void {
        _ = win32.CloseHandle(self.handle);
    }

    pub fn set(self: WakeEvent) void {
        _ = win32.SetEvent(self.handle);
    }

    pub const WaitResult = enum { signaled, timeout };

    pub fn timedWait(self: WakeEvent, timeout_ms: u32) WaitResult {
        return switch (win32.WaitForSingleObject(self.handle, timeout_ms)) {
            win32.WAIT_OBJECT_0 => .signaled,
            else => .timeout,
        };
    }
};

/// Exclusive-only SRWLOCK. Zero-init (`.{}`) is SRWLOCK_INIT; no teardown.
pub const Lock = struct {
    srw: win32.SRWLOCK = .{ .Ptr = null },

    pub fn lock(self: *Lock) void {
        win32.AcquireSRWLockExclusive(&self.srw);
    }

    pub fn unlock(self: *Lock) void {
        win32.ReleaseSRWLockExclusive(&self.srw);
    }
};

test "wake event auto-resets: one wait consumes the signal" {
    const ev = try WakeEvent.init();
    defer ev.deinit();
    try std.testing.expectEqual(WakeEvent.WaitResult.timeout, ev.timedWait(0));
    ev.set();
    ev.set(); // coalesces into the same single signal
    try std.testing.expectEqual(WakeEvent.WaitResult.signaled, ev.timedWait(0));
    try std.testing.expectEqual(WakeEvent.WaitResult.timeout, ev.timedWait(0));
}

test "wake event releases a waiting thread" {
    const ev = try WakeEvent.init();
    defer ev.deinit();
    const Waiter = struct {
        fn run(e: WakeEvent) void {
            _ = e.timedWait(win32.INFINITE);
        }
    };
    const t = try std.Thread.spawn(.{}, Waiter.run, .{ev});
    ev.set();
    t.join(); // would hang if the set never released the waiter
}

test "lock serializes two increment threads" {
    var lk: Lock = .{};
    var counter: u64 = 0;
    const Incr = struct {
        fn run(l: *Lock, c: *u64) void {
            for (0..10_000) |_| {
                l.lock();
                // Non-atomic on purpose: only the lock makes this safe.
                c.* += 1;
                l.unlock();
            }
        }
    };
    const a = try std.Thread.spawn(.{}, Incr.run, .{ &lk, &counter });
    const b = try std.Thread.spawn(.{}, Incr.run, .{ &lk, &counter });
    a.join();
    b.join();
    try std.testing.expectEqual(@as(u64, 20_000), counter);
}
