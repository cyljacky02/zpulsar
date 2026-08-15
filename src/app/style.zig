//! The window's palette and type scale, in one place because the Ledger and
//! the Info View have to agree: a dimmed value means the same thing in a table
//! cell as it does in the panel beside it, and the blue that marks the
//! selected line is the blue the panel titles it with.
//!
//! The colours are the ones the layout lock settled on (issue #10). Only the
//! ones the spec gives meaning to live here — everything else comes from the
//! theme, so the window still follows it.

const dvui = @import("dvui");
const engine = @import("engine");
const view = @import("view.zig");

const format = view.format;

/// Secondary text: PIDs, session totals, endpoints behind a hostname, the
/// status bar, and whole rows that have exited.
pub const dim: dvui.Color = .{ .r = 0x8a, .g = 0x8f, .b = 0x98 };
/// Reserved for the one thing the status bar can say that is bad news.
pub const warn: dvui.Color = .{ .r = 0xd8, .g = 0x60, .b = 0x60 };
/// The Info View's titles, and its reserved Tools entries.
pub const accent: dvui.Color = .{ .r = 0x4d, .g = 0xa8, .b = 0xe8 };
/// The selected line. Deep enough to read as chosen under the activity fills
/// that sit on top of it, dark enough to leave white text legible.
pub const selection: dvui.Color = .{ .r = 0x26, .g = 0x4f, .b = 0x78 };

/// Down is green and up is amber, everywhere either direction is coloured.
const down_fill: dvui.Color = .{ .r = 0x3f, .g = 0xb9, .b = 0x50 };
const up_fill: dvui.Color = .{ .r = 0xe8, .g = 0xa3, .b = 0x2b };

/// How to tint a Down or Up cell at this speed, or null for a cell with no
/// business being tinted. The scale is `view.activity`'s; the colours are the
/// window's.
pub fn activityFill(bytes_per_s: u64, dir: format.Direction) ?dvui.Color {
    const alpha = view.activity.fillAlpha(bytes_per_s) orelse return null;
    var color = switch (dir) {
        .down => down_fill,
        .up => up_fill,
    };
    color.a = alpha;
    return color;
}

/// One colour laid over another: the activity tint over whatever already
/// fills a line, so a selected row keeps its accent under its own speed. A
/// cell has one background, so the two have to be resolved into one colour
/// here rather than drawn on top of each other. With nothing behind it the
/// tint keeps its own alpha and blends over the table.
pub fn tinted(under: ?dvui.Color, tint: dvui.Color) dvui.Color {
    const base = under orelse return tint;
    return .{
        .r = mix(base.r, tint.r, tint.a),
        .g = mix(base.g, tint.g, tint.a),
        .b = mix(base.b, tint.b, tint.a),
        .a = base.a,
    };
}

fn mix(under: u8, over: u8, alpha: u8) u8 {
    const a: u16 = alpha;
    return @intCast((@as(u16, over) * a + @as(u16, under) * (255 - a)) / 255);
}

/// The protocol tag on a Flow's line. Distinct hues rather than distinct
/// letters alone, so the eye can sort a long flow list by shape.
pub fn protoFill(proto: engine.event.Proto) dvui.Color {
    return switch (proto) {
        .tcp => .{ .r = 0x3a, .g = 0x4a, .b = 0x63 },
        .udp => .{ .r = 0x4a, .g = 0x3a, .b = 0x63 },
        .icmp => .{ .r = 0x63, .g = 0x4a, .b = 0x2a },
    };
}

/// Text on a badge: light enough to read on every fill above.
pub const badge_text: dvui.Color = .{ .r = 0xc8, .g = 0xd0, .b = 0xdc };

/// Process badge colours, standing in for real exe icons in v1 (issue #10).
/// A row keeps its slot for the whole session — see `format.paletteSlot`.
pub const process_badges = [_]dvui.Color{
    .{ .r = 0x3f, .g = 0x8f, .b = 0xd0 },
    .{ .r = 0x4f, .g = 0xa8, .b = 0x5e },
    .{ .r = 0xc4, .g = 0x5c, .b = 0x50 },
    .{ .r = 0xd0, .g = 0x8f, .b = 0x3f },
    .{ .r = 0x8f, .g = 0x6f, .b = 0xc4 },
    .{ .r = 0x3f, .g = 0xa8, .b = 0xa0 },
    .{ .r = 0xc4, .g = 0x6f, .b = 0x9f },
    .{ .r = 0x7f, .g = 0x8f, .b = 0x5e },
};

/// Which badge colour a Process Row wears.
pub fn processBadge(name: []const u8) dvui.Color {
    return process_badges[format.paletteSlot(name, process_badges.len)];
}

/// Small text: everything that qualifies a line rather than being it —
/// endpoints under a hostname, flow counts, the Info View's fields.
pub fn caption() dvui.Font {
    const body = dvui.themeGet().font_body;
    return body.withSize(body.size - 3);
}

/// Small text with weight: section headings and the name at the top of the
/// Info View.
pub fn captionHeading() dvui.Font {
    const heading = dvui.themeGet().font_heading;
    return heading.withSize(heading.size - 3);
}

/// The Info View's one title, naming what is being inspected.
pub fn title() dvui.Font {
    return dvui.themeGet().font_title;
}
