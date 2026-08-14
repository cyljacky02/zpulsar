//! TDH fallback for unknown Kernel-Process payload versions
//! (docs/research/kernel-process-etw.md §Verdict: fields were inserted
//! between versions, so unknown layouts must never be parsed with old
//! offsets). Unlike the Kernel-Network fallback (tdh.zig), offsets cannot be
//! derived once per (id, version): v3+ payloads carry a variable-length SID
//! before ImageName, so fields are extracted per event via TdhGetProperty
//! against the OS-registered manifest schema. Affordable because this path
//! only runs on Windows builds newer than the implemented layouts, at
//! process-event volume (tens/s). Any failure means "drop", never misparse.

const std = @import("std");
const win32 = @import("win32");
const event = @import("event.zig");

/// Extract the fields the Engine needs from an unknown-version record.
/// Returns null when the schema lookup or a required property fails.
pub fn parse(rec: *win32.EVENT_RECORD, kind: event.ProcessKind) ?event.ProcessEvent {
    var out: event.ProcessEvent = .{
        .kind = kind,
        .pid = getFixed(u32, rec, "ProcessID") orelse return null,
        .create_time = getFixed(u64, rec, "CreateTime") orelse return null,
        .exit_time = 0,
        .name_len = 0,
        .name_buf = undefined,
    };
    switch (kind) {
        .stop => out.exit_time = getFixed(u64, rec, "ExitTime") orelse return null,
        // The stop-event name stays unread even here (research §2.4).
        .start, .rundown => readImageName(rec, &out),
    }
    return out;
}

/// A fixed-width property, dropped unless TDH reports exactly its size.
fn getFixed(comptime T: type, rec: *win32.EVENT_RECORD, comptime name: []const u8) ?T {
    var buf: [@sizeOf(T)]u8 = undefined;
    const size = getProperty(rec, name, &buf) orelse return null;
    if (size != @sizeOf(T)) return null;
    return std.mem.readInt(T, &buf, .little);
}

/// ImageName is a NUL-terminated UTF-16 string property. A missing or
/// oversized name leaves the record nameless — identity and lifetime still
/// work; only the display suffers.
fn readImageName(rec: *win32.EVENT_RECORD, out: *event.ProcessEvent) void {
    var buf: [4096]u8 = undefined;
    const size = getProperty(rec, "ImageName", &buf) orelse return;
    var n: usize = 0;
    while (2 * n + 1 < size and n < event.max_image_name_units) : (n += 1) {
        const unit = std.mem.readInt(u16, buf[2 * n ..][0..2], .little);
        if (unit == 0) break;
        out.name_buf[n] = unit;
    }
    out.name_len = @intCast(n);
}

/// One TdhGetPropertySize + TdhGetProperty round trip; null on any failure.
fn getProperty(rec: *win32.EVENT_RECORD, comptime name: []const u8, buf: []u8) ?u32 {
    var desc = [1]win32.PROPERTY_DATA_DESCRIPTOR{.{
        .PropertyName = @intFromPtr(std.unicode.utf8ToUtf16LeStringLiteral(name)),
        .ArrayIndex = std.math.maxInt(u32), // not an array property
        .Reserved = 0,
    }};
    var size: u32 = 0;
    if (win32.TdhGetPropertySize(rec, 0, null, 1, &desc, &size) != win32.ERROR_SUCCESS)
        return null;
    if (size == 0 or size > buf.len) return null;
    if (win32.TdhGetProperty(rec, 0, null, 1, &desc, size, @ptrCast(buf.ptr)) != win32.ERROR_SUCCESS)
        return null;
    return size;
}
