//! PROTOTYPE — Variant C "Pulse": dashboard-first. Global meters up top, processes as
//! ranked live activity bars (hot first), idle processes tucked below. Click to expand flows.
const std = @import("std");
const dvui = @import("dvui");
const data = @import("data.zig");
const common = @import("common.zig");

fn byActivity(_: void, a: data.ProcRow, b: data.ProcRow) bool {
    return (a.down_bps + a.up_bps) > (b.down_bps + b.up_bps);
}

fn isActive(p: *const data.ProcRow) bool {
    if (p.isIcmp()) return p.down_bps > 0.05;
    return (p.down_bps + p.up_bps) >= 256;
}

pub fn frame() void {
    std.mem.sort(data.ProcRow, data.procs, {}, byActivity);

    var vbox = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .both, .padding = .{ .x = 10, .y = 8, .w = 10, .h = 0 } });
    defer vbox.deinit();

    heroBand();

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both });
    defer scroll.deinit();

    dvui.label(@src(), "ACTIVE NOW", .{}, .{ .color_text = common.dim_text, .font = common.fontCaptionHeading(), .padding = .{ .x = 2, .y = 8, .w = 0, .h = 2 } });
    var shown: usize = 0;
    for (data.procs, 0..) |*p, i| {
        if (!isActive(p)) continue;
        activeRow(p, i);
        shown += 1;
    }
    if (shown == 0) {
        dvui.label(@src(), "nothing is talking right now", .{}, .{ .color_text = common.dim_text });
    }

    dvui.label(@src(), "IDLE", .{}, .{ .color_text = common.dim_text, .font = common.fontCaptionHeading(), .padding = .{ .x = 2, .y = 12, .w = 0, .h = 2 } });
    for (data.procs, 0..) |*p, i| {
        if (isActive(p)) continue;
        idleRow(p, i);
    }
}

fn heroBand() void {
    var band = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
    defer band.deinit();
    meterTile(0, "DOWNLOAD", data.global_down_bps, data.global_down_total, common.down_color);
    meterTile(1, "UPLOAD", data.global_up_bps, data.global_up_total, common.up_color);
}

fn meterTile(id: usize, title: []const u8, bps: f64, total: f64, accent: dvui.Color) void {
    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;

    var tile = dvui.box(@src(), .{ .dir = .vertical }, .{
        .id_extra = id,
        .expand = .horizontal,
        .background = true,
        .style = .control,
        .corners = .all(10),
        .margin = .{ .x = 0, .y = 0, .w = if (id == 0) 10 else 0, .h = 0 },
        .padding = .{ .x = 12, .y = 8, .w = 12, .h = 10 },
    });
    defer tile.deinit();

    dvui.label(@src(), "{s}", .{title}, .{ .color_text = common.dim_text, .font = common.fontCaptionHeading() });
    dvui.label(@src(), "{s}", .{common.fmtSpeed(&buf1, bps)}, .{ .font = common.fontBig(), .color_text = accent });
    dvui.progress(@src(), .{ .percent = common.activity(bps), .color = accent }, .{
        .expand = .horizontal,
        .min_size_content = .{ .h = 6 },
        .corners = .all(3),
        .margin = .{ .x = 0, .y = 4, .w = 0, .h = 4 },
    });
    dvui.label(@src(), "session {s}", .{common.fmtBytes(&buf2, total)}, .{ .color_text = common.dim_text, .font = common.fontCaption() });
}

fn activeRow(p: *data.ProcRow, i: usize) void {
    var buf1: [48]u8 = undefined;

    var bw: dvui.ButtonWidget = undefined;
    bw.init(@src(), .{}, .{
        .id_extra = i,
        .expand = .horizontal,
        .background = true,
        .color_fill = dvui.themeGet().color(.content, .fill),
        .corners = .all(8),
        .margin = .{ .x = 0, .y = 1, .w = 6, .h = 1 },
        .padding = .{ .x = 6, .y = 4, .w = 8, .h = 4 },
    });
    bw.processEvents();
    bw.drawBackground();
    {
        var row = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer row.deinit();

        common.procBadge(p, .{});
        {
            var namebox = dvui.box(@src(), .{ .dir = .vertical }, .{ .gravity_y = 0.5, .min_size_content = .{ .w = 230 } });
            defer namebox.deinit();
            dvui.label(@src(), "{s}", .{p.name}, .{});
            if (p.service) |svc| {
                dvui.label(@src(), "{s}", .{svc}, .{ .color_text = common.dim_text, .font = common.fontCaption() });
            }
        }
        if (p.isIcmp()) {
            dvui.label(@src(), "{s}", .{common.fmtMsgRate(&buf1, p.down_bps)}, .{ .gravity_x = 1.0, .gravity_y = 0.5, .color_text = common.dim_text });
        } else {
            {
                var bars = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .horizontal, .gravity_y = 0.5, .padding = .{ .x = 8, .y = 0, .w = 8, .h = 0 } });
                defer bars.deinit();
                dvui.progress(@src(), .{ .percent = common.activity(p.down_bps), .color = common.down_color }, .{
                    .expand = .horizontal,
                    .min_size_content = .{ .h = 5 },
                    .corners = .all(2),
                    .margin = .{ .x = 0, .y = 1, .w = 0, .h = 1 },
                });
                dvui.progress(@src(), .{ .percent = common.activity(p.up_bps), .color = common.up_color }, .{
                    .expand = .horizontal,
                    .min_size_content = .{ .h = 5 },
                    .corners = .all(2),
                    .margin = .{ .x = 0, .y = 1, .w = 0, .h = 1 },
                });
            }
            {
                var speeds = dvui.box(@src(), .{ .dir = .vertical }, .{ .gravity_x = 1.0, .gravity_y = 0.5, .min_size_content = .{ .w = 92 } });
                defer speeds.deinit();
                common.speedLabel(false, p.down_bps, common.fontCaption(), common.down_color, .{ .gravity_x = 1.0 });
                common.speedLabel(true, p.up_bps, common.fontCaption(), common.up_color, .{ .id_extra = 1, .gravity_x = 1.0 });
            }
        }
    }
    bw.drawFocus();
    if (bw.clicked()) p.expanded = !p.expanded;
    bw.deinit();

    if (p.expanded) {
        for (p.flows, 0..) |*f, fi| {
            flowLine(f, i * 16 + fi);
        }
    }
}

fn flowLine(f: *data.Flow, id: usize) void {
    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;

    var row = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .id_extra = id,
        .expand = .horizontal,
        .margin = .{ .x = 26, .y = 0, .w = 6, .h = 0 },
        .padding = .{ .x = 4, .y = 1, .w = 8, .h = 1 },
    });
    defer row.deinit();

    common.protoBadge(f.proto, .{});
    if (f.hostname) |h| {
        dvui.label(@src(), "{s}", .{h}, .{ .gravity_y = 0.5, .color_text = if (f.reverse_fallback) common.dim_text else null });
        dvui.label(@src(), "{s}", .{f.endpoint}, .{ .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
    } else {
        dvui.label(@src(), "{s}", .{f.endpoint}, .{ .gravity_y = 0.5 });
    }
    if (f.proto == .icmp) {
        dvui.label(@src(), "{s} · {s}", .{ common.fmtMsgRate(&buf1, f.down_bps), common.fmtMsgTotal(&buf2, f.down_total) }, .{ .gravity_x = 1.0, .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
    } else {
        var speeds = dvui.box(@src(), .{ .dir = .horizontal }, .{ .gravity_x = 1.0, .gravity_y = 0.5 });
        defer speeds.deinit();
        common.speedLabel(false, f.down_bps, common.fontCaption(), common.dim_text, .{ .gravity_y = 0.5 });
        common.speedLabel(true, f.up_bps, common.fontCaption(), common.dim_text, .{ .id_extra = 1, .gravity_y = 0.5, .margin = .{ .x = 8, .y = 0, .w = 0, .h = 0 } });
    }
}

fn idleRow(p: *data.ProcRow, i: usize) void {
    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;

    var row = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .id_extra = i,
        .expand = .horizontal,
        .padding = .{ .x = 6, .y = 2, .w = 8, .h = 2 },
    });
    defer row.deinit();

    common.procBadge(p, .{});
    dvui.label(@src(), "{s}", .{p.name}, .{ .gravity_y = 0.5, .color_text = common.dim_text });
    if (p.service) |svc| {
        dvui.label(@src(), "{s}", .{svc}, .{ .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
    }
    dvui.label(@src(), "session {s} down / {s} up", .{
        common.fmtBytes(&buf1, p.down_total),
        common.fmtBytes(&buf2, p.up_total),
    }, .{ .gravity_x = 1.0, .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
}
