//! PROTOTYPE — shared formatting + small widgets used by all variants.
const std = @import("std");
const dvui = @import("dvui");
const data = @import("data.zig");

pub const dim_text: dvui.Color = .{ .r = 0x8a, .g = 0x8f, .b = 0x98 };
pub const down_color: dvui.Color = .{ .r = 0x3f, .g = 0xb9, .b = 0x50 };
pub const up_color: dvui.Color = .{ .r = 0xe8, .g = 0xa3, .b = 0x2b };

const KB = 1024.0;
const MB = 1024.0 * 1024.0;
const GB = 1024.0 * 1024.0 * 1024.0;

pub fn fontCaption() dvui.Font {
    const body = dvui.themeGet().font_body;
    return body.withSize(body.size - 3);
}

pub fn fontCaptionHeading() dvui.Font {
    const heading = dvui.themeGet().font_heading;
    return heading.withSize(heading.size - 3);
}

pub fn fontTitle() dvui.Font {
    return dvui.themeGet().font_title;
}

pub fn fontBig() dvui.Font {
    const title = dvui.themeGet().font_title;
    return title.withSize(title.size + 6);
}

/// "12.4 MB/s", "832 KB/s", "—" below 1 B/s
pub fn fmtSpeed(buf: []u8, bps: f64) []const u8 {
    if (bps < 1) return "—";
    if (bps >= MB) return std.fmt.bufPrint(buf, "{d:.1} MB/s", .{bps / MB}) catch "?";
    if (bps >= KB) return std.fmt.bufPrint(buf, "{d:.0} KB/s", .{bps / KB}) catch "?";
    return std.fmt.bufPrint(buf, "{d:.0} B/s", .{bps}) catch "?";
}

/// "1.24 GB", "832 KB", "—" for zero
pub fn fmtBytes(buf: []u8, bytes: f64) []const u8 {
    if (bytes < 1) return "—";
    if (bytes >= GB) return std.fmt.bufPrint(buf, "{d:.2} GB", .{bytes / GB}) catch "?";
    if (bytes >= MB) return std.fmt.bufPrint(buf, "{d:.1} MB", .{bytes / MB}) catch "?";
    if (bytes >= KB) return std.fmt.bufPrint(buf, "{d:.0} KB", .{bytes / KB}) catch "?";
    return std.fmt.bufPrint(buf, "{d:.0} B", .{bytes}) catch "?";
}

/// ICMP has no per-flow byte counts user-mode — message counts instead.
pub fn fmtMsgRate(buf: []u8, per_s: f64) []const u8 {
    if (per_s < 0.05) return "—";
    return std.fmt.bufPrint(buf, "{d:.1} msg/s", .{per_s}) catch "?";
}

pub fn fmtMsgTotal(buf: []u8, count: f64) []const u8 {
    if (count < 1) return "—";
    return std.fmt.bufPrint(buf, "{d:.0} msgs", .{count}) catch "?";
}

/// 0..1 activity on a log scale: 1 KB/s -> 0, 50 MB/s -> 1.
pub fn activity(bps: f64) f32 {
    if (bps < KB) return 0;
    const v = std.math.log10(bps / KB) / std.math.log10(50.0 * MB / KB);
    return @floatCast(std.math.clamp(v, 0.0, 1.0));
}

/// Cell fill for the down/up speed columns; null when idle.
pub fn speedFill(bps: f64, up: bool) ?dvui.Color {
    const a = activity(bps);
    if (a <= 0) return null;
    const alpha: u8 = @intFromFloat(24.0 + 96.0 * a);
    var c = if (up) up_color else down_color;
    c.a = alpha;
    return c;
}

/// "▲/▼ 12.4 MB/s" as icon + text (the UI font has no arrow glyphs).
/// Caller provides layout opts for the wrapping hbox (id_extra, gravity, ...).
pub fn speedLabel(up: bool, bps: f64, font: dvui.Font, color: ?dvui.Color, opts: dvui.Options) void {
    var buf: [48]u8 = undefined;
    var hbox = dvui.box(@src(), .{ .dir = .horizontal }, opts);
    defer hbox.deinit();
    const tvg = if (up) dvui.entypo.arrow_bold_up else dvui.entypo.arrow_bold_down;
    dvui.icon(@src(), "arr", tvg, .{}, .{
        .gravity_y = 0.5,
        .min_size_content = .{ .w = 9, .h = 9 },
        .color_text = color orelse dim_text,
        .margin = .{ .x = 0, .y = 0, .w = 3, .h = 0 },
    });
    dvui.label(@src(), "{s}", .{fmtSpeed(&buf, bps)}, .{ .font = font, .color_text = color, .gravity_y = 0.5 });
}

/// Round colored badge with the process's first letter — stand-in for the exe icon.
pub fn procBadge(p: *const data.ProcRow, opts: dvui.Options) void {
    const letter = [1]u8{std.ascii.toUpper(p.name[0])};
    dvui.label(@src(), "{s}", .{&letter}, (dvui.Options{
        .background = true,
        .color_fill = .{ .r = p.color[0], .g = p.color[1], .b = p.color[2] },
        .color_text = .{ .r = 0xff, .g = 0xff, .b = 0xff },
        .corners = .all(100),
        .min_size_content = .{ .w = 13, .h = 13 },
        .padding = .{ .x = 4, .y = 1, .w = 4, .h = 1 },
        .margin = .{ .x = 2, .y = 2, .w = 4, .h = 2 },
        .gravity_y = 0.5,
        .font = fontCaptionHeading(),
    }).override(opts));
}

pub fn protoLabel(p: data.Proto) []const u8 {
    return switch (p) {
        .tcp => "TCP",
        .udp => "UDP",
        .icmp => "ICMP",
    };
}

/// Small square proto tag ("TCP"/"UDP"/"ICMP").
pub fn protoBadge(proto: data.Proto, opts: dvui.Options) void {
    const fill: dvui.Color = switch (proto) {
        .tcp => .{ .r = 0x3a, .g = 0x4a, .b = 0x63 },
        .udp => .{ .r = 0x4a, .g = 0x3a, .b = 0x63 },
        .icmp => .{ .r = 0x63, .g = 0x4a, .b = 0x2a },
    };
    dvui.label(@src(), "{s}", .{protoLabel(proto)}, (dvui.Options{
        .background = true,
        .color_fill = fill,
        .color_text = .{ .r = 0xc8, .g = 0xd0, .b = 0xdc },
        .corners = .all(3),
        .padding = .{ .x = 3, .y = 0, .w = 3, .h = 0 },
        .margin = .{ .x = 2, .y = 2, .w = 4, .h = 2 },
        .gravity_y = 0.5,
        .font = fontCaption(),
    }).override(opts));
}
