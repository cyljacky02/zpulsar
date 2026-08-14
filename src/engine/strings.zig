//! Session-lifetime string interning for the handful of names the Engine
//! repeats everywhere: Windows service names (issue #25). A service name is
//! referenced by its Process Row's hosted-service list, by every Flow that
//! resolved to it, and by every Snapshot built while either lives — but the
//! set of distinct names is tiny and bounded by what the machine has
//! installed. Interning makes those references plain slices with one owner
//! and no lifetime question: a name, once interned, is valid for the rest of
//! the session, so a service map replacing its predecessor can never dangle a
//! Flow's service name.
//!
//! Names are never evicted. That is the point — an eviction policy would
//! reintroduce exactly the dangling-reference problem this exists to remove,
//! and the ceiling (a few hundred short strings) is far below any budget.

const std = @import("std");

pub const Pool = struct {
    /// The set owns its keys; the void values make it a set.
    set: std.StringHashMapUnmanaged(void) = .empty,

    pub fn deinit(self: *Pool, gpa: std.mem.Allocator) void {
        var it = self.set.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
        self.set.deinit(gpa);
    }

    /// The pool's copy of `text` — the same slice for every equal string.
    pub fn intern(
        self: *Pool,
        gpa: std.mem.Allocator,
        text: []const u8,
    ) error{OutOfMemory}![]const u8 {
        const gop = try self.set.getOrPut(gpa, text);
        if (gop.found_existing) return gop.key_ptr.*;
        // getOrPut stored the caller's slice as the key; own it before
        // returning, and un-store it if that fails — the map must never hold
        // a key it doesn't own.
        gop.key_ptr.* = gpa.dupe(u8, text) catch |err| {
            _ = self.set.remove(text);
            return err;
        };
        return gop.key_ptr.*;
    }

    pub fn count(self: *const Pool) usize {
        return self.set.count();
    }
};

test "equal strings intern to one allocation, different ones stay distinct" {
    const gpa = std.testing.allocator;
    var pool: Pool = .{};
    defer pool.deinit(gpa);

    // Separate buffers with equal contents: interning must collapse them.
    var buf: [8]u8 = undefined;
    @memcpy(buf[0..5], "RpcSs");
    const a = try pool.intern(gpa, "RpcSs");
    const b = try pool.intern(gpa, buf[0..5]);
    try std.testing.expectEqual(a.ptr, b.ptr);
    try std.testing.expectEqualStrings("RpcSs", a);

    const c = try pool.intern(gpa, "Dnscache");
    try std.testing.expect(a.ptr != c.ptr);
    try std.testing.expectEqual(@as(usize, 2), pool.count());
}

test "an interned name outlives the buffer it was interned from" {
    const gpa = std.testing.allocator;
    var pool: Pool = .{};
    defer pool.deinit(gpa);

    const scratch = try gpa.dupe(u8, "MpsSvc");
    const interned = try pool.intern(gpa, scratch);
    gpa.free(scratch); // the source is gone; the pool's copy is not
    try std.testing.expectEqualStrings("MpsSvc", interned);
}
