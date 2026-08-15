//! What the status bar and the tray tooltip say: one pass over a Snapshot for
//! the whole-machine numbers, and the text the tray icon carries between them.
//! Pure — a Snapshot in, text out — so the aggregation rules are testable
//! without a window, which matters because the tooltip is the *only* surface
//! left in Tray-idle.

const std = @import("std");
const engine = @import("engine");
const format = @import("format.zig");

/// The whole machine, right now.
pub const Totals = struct {
    /// Live Flows only: a Lingering Flow is a closed conversation still on
    /// screen (CONTEXT.md "Linger"), and counting it as active would say the
    /// machine is busier than it is.
    active_flows: usize = 0,
    down_rate: u64 = 0,
    up_rate: u64 = 0,
    /// In-session Totals, summed across every row — exited and evicted
    /// included, because their bytes are still this session's bytes.
    session_recv: u64 = 0,
    session_sent: u64 = 0,
    /// The busiest Process Row, borrowed from the Snapshot — so it lives
    /// exactly as long as the Snapshot the caller is holding. Null when
    /// nothing is moving.
    top_talker: ?[]const u8 = null,
    top_talker_rate: u64 = 0,
};

pub fn of(snap: *const engine.snapshot.Snapshot) Totals {
    var t: Totals = .{};
    for (snap.rows) |r| {
        t.down_rate += r.recv_rate;
        t.up_rate += r.sent_rate;
        t.session_recv += r.recv;
        t.session_sent += r.sent;
        const row_rate = r.recv_rate + r.sent_rate;
        if (row_rate > t.top_talker_rate) {
            t.top_talker_rate = row_rate;
            t.top_talker = format.processName(r.name);
        }
    }
    for (snap.flows) |f| {
        if (!f.lingering) t.active_flows += 1;
    }
    return t;
}

/// Shell_NotifyIcon's tooltip field is 128 UTF-16 units including the
/// terminator (NOTIFYICONDATAW.szTip). Every byte here is ASCII or a BMP
/// character, so a byte fits in at most one UTF-16 unit and bounding the UTF-8
/// length bounds the conversion — with room left for the terminator.
pub const tooltip_buf_len = 127;
/// A process name long enough to push the speeds out of the tooltip is a
/// process name nobody needs in full.
const top_talker_name_limit = 40;

/// What the tray icon says while the window is gone: the machine's speeds, and
/// who is responsible for them. Two lines — Shell_NotifyIcon renders the
/// newline, and the top talker is the answer to the question the speeds raise.
pub fn tooltip(buf: *[tooltip_buf_len]u8, t: Totals) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    if (t.down_rate == 0 and t.up_rate == 0) {
        w.writeAll("zPulsar — idle") catch {};
        return w.buffered();
    }
    var down: [format.rate_buf_len]u8 = undefined;
    var up: [format.rate_buf_len]u8 = undefined;
    w.print("zPulsar — down {s}  up {s}", .{
        format.rate(&down, t.down_rate),
        format.rate(&up, t.up_rate),
    }) catch return w.buffered();
    if (t.top_talker) |name| {
        var busiest: [format.rate_buf_len]u8 = undefined;
        w.print("\n{s}  {s}", .{
            format.truncate(name, top_talker_name_limit),
            format.rate(&busiest, t.top_talker_rate),
        }) catch {}; // the speeds already written are the load-bearing half
    }
    return w.buffered();
}

const testing = std.testing;
const snapshot = engine.snapshot;

/// A Snapshot built by hand, with `rows` and `flows` unattached to each other
/// — everything here aggregates over the flat arrays.
fn testSnapshot(rows: []const snapshot.Row, flows: []const snapshot.Flow) !*snapshot.Snapshot {
    const snap = try snapshot.create(testing.allocator, rows.len, flows.len);
    for (snapshot.mutableRows(snap), rows) |*dst, src| {
        dst.* = src;
        dst.name = try snapshot.arenaDupe(snap, src.name);
    }
    @memcpy(snapshot.mutableFlows(snap), flows);
    return snap;
}

test "the status bar's numbers are the whole machine, exited rows included" {
    const snap = try testSnapshot(&.{
        .{ .pid = 1, .name = "C:\\a.exe", .recv_rate = 1000, .sent_rate = 10, .recv = 5000, .sent = 50 },
        // An exited row moves no bytes now, but its bytes are still the
        // session's (CONTEXT.md "In-session Totals").
        .{ .pid = 2, .name = "C:\\b.exe", .exited = true, .recv = 300, .sent = 7 },
        .{ .pid = 3, .name = "C:\\c.exe", .recv_rate = 25, .sent_rate = 5, .recv = 90, .sent = 1 },
    }, &.{
        .{ .proto = .tcp, .family = .v4, .local_addr = @splat(0), .remote_addr = @splat(0), .local_port = 1, .remote_port = 2, .generation = 1 },
        .{ .proto = .tcp, .family = .v4, .local_addr = @splat(0), .remote_addr = @splat(0), .local_port = 3, .remote_port = 4, .generation = 1, .lingering = true },
        .{ .proto = .udp, .family = .v4, .local_addr = @splat(0), .remote_addr = @splat(0), .local_port = 5, .remote_port = 6, .generation = 1 },
    });
    defer snap.release();

    const t = of(snap);
    try testing.expectEqual(@as(u64, 1025), t.down_rate);
    try testing.expectEqual(@as(u64, 15), t.up_rate);
    try testing.expectEqual(@as(u64, 5390), t.session_recv);
    try testing.expectEqual(@as(u64, 58), t.session_sent);
    // Two live Flows and one Lingering: the Lingering one is not activity.
    try testing.expectEqual(@as(usize, 2), t.active_flows);
    try testing.expectEqualStrings("a.exe", t.top_talker.?);
    try testing.expectEqual(@as(u64, 1010), t.top_talker_rate);
}

test "an idle machine names no top talker, and says so" {
    const snap = try testSnapshot(&.{
        .{ .pid = 1, .name = "C:\\a.exe", .recv = 5000 },
    }, &.{});
    defer snap.release();

    const t = of(snap);
    try testing.expectEqual(@as(?[]const u8, null), t.top_talker);
    var buf: [tooltip_buf_len]u8 = undefined;
    try testing.expectEqualStrings("zPulsar — idle", tooltip(&buf, t));
}

test "the tooltip carries the speeds and who is responsible for them" {
    var buf: [tooltip_buf_len]u8 = undefined;
    const text = tooltip(&buf, .{
        .down_rate = 1_500_000,
        .up_rate = 2_000,
        .top_talker = "chrome.exe",
        .top_talker_rate = 1_400_000,
    });
    try testing.expectEqualStrings("zPulsar — down 1.5 MB/s  up 2.0 KB/s\nchrome.exe  1.4 MB/s", text);
}

test "an absurd process name cannot push the tooltip past what the tray accepts" {
    var buf: [tooltip_buf_len]u8 = undefined;
    const text = tooltip(&buf, .{
        .down_rate = 1_500_000,
        .up_rate = 2_000,
        .top_talker = "ααααααααααααααααααααααααααααααααααααααααααααααααααααααααααααααααααααααα",
        .top_talker_rate = 1_400_000,
    });
    try testing.expect(text.len <= tooltip_buf_len);
    // The speeds survive: they are the half the tooltip exists for.
    try testing.expect(std.mem.startsWith(u8, text, "zPulsar — down 1.5 MB/s  up 2.0 KB/s\n"));
    // And the name is cut on a character boundary, not mid-sequence.
    try testing.expect(std.unicode.utf8ValidateSlice(text));
}
