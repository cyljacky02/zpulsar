//! PROTOTYPE — floating variant-switcher bar. Not part of the design under evaluation.
const std = @import("std");
const dvui = @import("dvui");
const state = @import("state.zig");
const common = @import("common.zig");

pub fn frame() void {
    // keyboard: left/right cycles variants (only if nothing else consumed the key)
    for (dvui.events()) |*e| {
        if (e.handled) continue;
        if (e.evt == .key and e.evt.key.action == .down) {
            switch (e.evt.key.code) {
                .left => state.variant = state.variant.prev(),
                .right => state.variant = state.variant.next(),
                else => {},
            }
        }
    }

    const wr = dvui.windowRect();
    const bar_w: f32 = 470;
    var rect: dvui.Rect = .{
        .x = @max(0, (wr.w - bar_w) / 2),
        .y = @max(0, wr.h - 52),
        .w = bar_w,
        .h = 38,
    };
    var fw = dvui.floatingWindow(@src(), .{
        .rect = &rect,
        .resize = .none,
        .window_avoid = .none,
    }, .{
        .background = true,
        .color_fill = .{ .r = 0x14, .g = 0x16, .b = 0x1c, .a = 0xf2 },
        .corners = .all(19),
        .border = dvui.Rect.all(1),
        .color_border = .{ .r = 0x3c, .g = 0x41, .b = 0x4c },
        .padding = .{ .x = 10, .y = 2, .w = 10, .h = 2 },
    });
    defer fw.deinit();

    var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .both });
    defer hbox.deinit();

    if (dvui.button(@src(), "<", .{}, .{ .gravity_y = 0.5, .corners = .all(12) })) {
        state.variant = state.variant.prev();
    }
    dvui.label(@src(), "{s}", .{state.variant.title()}, .{
        .gravity_y = 0.5,
        .min_size_content = .{ .w = 250 },
        .gravity_x = 0.5,
    });
    if (dvui.button(@src(), ">", .{}, .{ .gravity_y = 0.5, .corners = .all(12) })) {
        state.variant = state.variant.next();
    }
    dvui.label(@src(), "arrows switch · cycle {d}", .{state.cycle}, .{
        .gravity_y = 0.5,
        .gravity_x = 1.0,
        .color_text = .{ .r = 0x8a, .g = 0x8f, .b = 0x98 },
        .font = common.fontCaption(),
    });
}
