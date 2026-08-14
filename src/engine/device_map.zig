//! NT device path → drive-letter conversion for display
//! (docs/research/kernel-process-etw.md §2.3): start/rundown payloads carry
//! the kernel's image path, `\Device\HarddiskVolumeN\...`; the UI wants
//! `C:\...`. Purely a display concern — rows key and cache on the raw
//! payload string, never on the converted one. Paths outside the mapping
//! (`\Device\Mup\...` network images, bare kernel-process names) pass
//! through unchanged.

const std = @import("std");
const win32 = @import("win32");

pub const DriveMap = struct {
    pub const Entry = struct {
        /// Device target without trailing backslash, UTF-8,
        /// e.g. "\Device\HarddiskVolume3".
        device: []u8,
        /// 'A'–'Z'.
        letter: u8,
    };

    entries: []Entry = &.{},

    pub fn deinit(self: *DriveMap, gpa: std.mem.Allocator) void {
        for (self.entries) |e| gpa.free(e.device);
        gpa.free(self.entries);
        self.entries = &.{};
    }

    /// Owned display string for a payload image name: the matching device
    /// prefix swapped for "C:", anything unmatched copied as-is. The prefix
    /// must be followed by a path separator — "\Device\HarddiskVolume3" must
    /// not claim "\Device\HarddiskVolume31\...".
    pub fn displayPath(
        self: DriveMap,
        gpa: std.mem.Allocator,
        nt_path: []const u8,
    ) error{OutOfMemory}![]u8 {
        for (self.entries) |e| {
            if (nt_path.len > e.device.len and nt_path[e.device.len] == '\\' and
                std.ascii.startsWithIgnoreCase(nt_path, e.device))
            {
                const rest = nt_path[e.device.len..];
                const out = try gpa.alloc(u8, 2 + rest.len);
                out[0] = e.letter;
                out[1] = ':';
                @memcpy(out[2..], rest);
                return out;
            }
        }
        return gpa.dupe(u8, nt_path);
    }
};

/// Production snapshot: one QueryDosDeviceW per present logical drive.
/// Letters whose query fails are skipped — their paths just display raw.
/// Refresh-on-device-change is a later ticket; the map is built once at
/// Engine start.
pub fn query(gpa: std.mem.Allocator) error{OutOfMemory}!DriveMap {
    var entries: std.ArrayList(DriveMap.Entry) = .empty;
    errdefer {
        for (entries.items) |e| gpa.free(e.device);
        entries.deinit(gpa);
    }

    const mask = win32.GetLogicalDrives();
    var letter: u8 = 'A';
    while (letter <= 'Z') : (letter += 1) {
        if (mask >> @intCast(letter - 'A') & 1 == 0) continue;
        const device_name = [3:0]u16{ letter, ':', 0 };
        // Target is a double-NUL MULTI_SZ; the first entry is the current
        // mapping. 512 chars dwarfs any real "\Device\HarddiskVolumeN".
        var target: [512:0]u16 = undefined;
        const copied = win32.QueryDosDeviceW(&device_name, &target, target.len);
        if (copied == 0) continue;
        const first = std.mem.sliceTo(target[0..copied], 0);
        const device = std.unicode.wtf16LeToWtf8Alloc(gpa, first) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
        };
        try entries.append(gpa, .{ .device = device, .letter = letter });
    }
    return .{ .entries = try entries.toOwnedSlice(gpa) };
}

// ---------------------------------------------------------------------------
// Tests — the pure conversion; the live QueryDosDeviceW snapshot is
// exercised through the headless rig.
// ---------------------------------------------------------------------------

fn testMap(gpa: std.mem.Allocator) !DriveMap {
    const entries = try gpa.alloc(DriveMap.Entry, 2);
    entries[0] = .{ .device = try gpa.dupe(u8, "\\Device\\HarddiskVolume3"), .letter = 'C' };
    entries[1] = .{ .device = try gpa.dupe(u8, "\\Device\\HarddiskVolume7"), .letter = 'D' };
    return .{ .entries = entries };
}

test "device prefixes convert to their drive letters" {
    const gpa = std.testing.allocator;
    var map = try testMap(gpa);
    defer map.deinit(gpa);

    const c = try map.displayPath(gpa, "\\Device\\HarddiskVolume3\\Windows\\System32\\PING.EXE");
    defer gpa.free(c);
    try std.testing.expectEqualStrings("C:\\Windows\\System32\\PING.EXE", c);

    const d = try map.displayPath(gpa, "\\Device\\HarddiskVolume7\\tools\\zig.exe");
    defer gpa.free(d);
    try std.testing.expectEqualStrings("D:\\tools\\zig.exe", d);
}

test "matching is case-insensitive (device namespace is)" {
    const gpa = std.testing.allocator;
    var map = try testMap(gpa);
    defer map.deinit(gpa);
    const out = try map.displayPath(gpa, "\\device\\harddiskvolume3\\x.exe");
    defer gpa.free(out);
    try std.testing.expectEqualStrings("C:\\x.exe", out);
}

test "a longer volume number is not claimed by its prefix" {
    const gpa = std.testing.allocator;
    var map = try testMap(gpa);
    defer map.deinit(gpa);
    // Volume31 starts with Volume3's text; it must pass through unchanged.
    const out = try map.displayPath(gpa, "\\Device\\HarddiskVolume31\\evil.exe");
    defer gpa.free(out);
    try std.testing.expectEqualStrings("\\Device\\HarddiskVolume31\\evil.exe", out);
}

test "unmapped paths and bare kernel-process names pass through" {
    const gpa = std.testing.allocator;
    var map = try testMap(gpa);
    defer map.deinit(gpa);

    const mup = try map.displayPath(gpa, "\\Device\\Mup\\server\\share\\tool.exe");
    defer gpa.free(mup);
    try std.testing.expectEqualStrings("\\Device\\Mup\\server\\share\\tool.exe", mup);

    const bare = try map.displayPath(gpa, "MemCompression");
    defer gpa.free(bare);
    try std.testing.expectEqualStrings("MemCompression", bare);

    // An empty map (query failed wholesale) still yields usable raw paths.
    var empty: DriveMap = .{};
    defer empty.deinit(gpa);
    const raw = try empty.displayPath(gpa, "\\Device\\HarddiskVolume3\\a.exe");
    defer gpa.free(raw);
    try std.testing.expectEqualStrings("\\Device\\HarddiskVolume3\\a.exe", raw);
}
