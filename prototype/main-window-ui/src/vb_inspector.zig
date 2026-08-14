//! PROTOTYPE — Variant B "Inspector": master–detail. Process list on the left
//! (always sorted by live activity), full flow detail for the selection on the right.
const std = @import("std");
const dvui = @import("dvui");
const data = @import("data.zig");
const state = @import("state.zig");
const common = @import("common.zig");

fn byActivity(_: void, a: data.ProcRow, b: data.ProcRow) bool {
    return (a.down_bps + a.up_bps) > (b.down_bps + b.up_bps);
}

pub fn frame() void {
    std.mem.sort(data.ProcRow, data.procs, {}, byActivity);

    var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .both });
    defer hbox.deinit();

    processList();
    _ = dvui.separator(@src(), .{ .expand = .vertical });
    detailPanel(state.findSelected());
}

fn processList() void {
    var vbox = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .vertical, .min_size_content = .{ .w = 300 } });
    defer vbox.deinit();

    dvui.label(@src(), "PROCESSES — by activity", .{}, .{ .color_text = common.dim_text, .font = common.fontCaptionHeading(), .padding = .{ .x = 6, .y = 4, .w = 0, .h = 2 } });

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both });
    defer scroll.deinit();

    var buf1: [48]u8 = undefined;

    for (data.procs, 0..) |*p, i| {
        const selected = p.pid == state.selected_pid;
        var bw: dvui.ButtonWidget = undefined;
        bw.init(@src(), .{}, .{
            .id_extra = i,
            .expand = .horizontal,
            .background = true,
            .color_fill = if (selected) dvui.themeGet().color(.control, .fill_press) else dvui.themeGet().color(.content, .fill),
            .corners = .all(6),
            .margin = .{ .x = 4, .y = 1, .w = 4, .h = 1 },
            .padding = .{ .x = 4, .y = 3, .w = 6, .h = 3 },
        });
        bw.processEvents();
        bw.drawBackground();
        {
            var row = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
            defer row.deinit();

            common.procBadge(p, .{});
            {
                var namebox = dvui.box(@src(), .{ .dir = .vertical }, .{ .gravity_y = 0.5 });
                defer namebox.deinit();
                dvui.label(@src(), "{s}", .{p.name}, .{});
                if (p.service) |svc| {
                    dvui.label(@src(), "{s}", .{svc}, .{ .color_text = common.dim_text, .font = common.fontCaption() });
                }
            }
            {
                var speeds = dvui.box(@src(), .{ .dir = .vertical }, .{ .gravity_x = 1.0, .gravity_y = 0.5 });
                defer speeds.deinit();
                if (p.isIcmp()) {
                    dvui.label(@src(), "{s}", .{common.fmtMsgRate(&buf1, p.down_bps)}, .{ .font = common.fontCaption(), .gravity_x = 1.0, .color_text = common.dim_text });
                } else {
                    const active_down = p.down_bps >= 1;
                    const active_up = p.up_bps >= 1;
                    common.speedLabel(false, p.down_bps, common.fontCaption(), if (active_down) common.down_color else common.dim_text, .{ .gravity_x = 1.0 });
                    common.speedLabel(true, p.up_bps, common.fontCaption(), if (active_up) common.up_color else common.dim_text, .{ .id_extra = 1, .gravity_x = 1.0 });
                }
            }
        }
        bw.drawFocus();
        if (bw.clicked()) state.selected_pid = p.pid;
        bw.deinit();
    }
}

fn detailPanel(p: *data.ProcRow) void {
    var vbox = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .both, .padding = .{ .x = 10, .y = 6, .w = 10, .h = 0 } });
    defer vbox.deinit();

    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;

    {
        var head = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer head.deinit();
        common.procBadge(p, .{ .font = common.fontTitle(), .min_size_content = .{ .w = 22, .h = 22 }, .padding = .{ .x = 7, .y = 3, .w = 7, .h = 3 } });
        {
            var namebox = dvui.box(@src(), .{ .dir = .vertical }, .{ .gravity_y = 0.5 });
            defer namebox.deinit();
            dvui.label(@src(), "{s}", .{p.name}, .{ .font = common.fontTitle() });
            if (p.service) |svc| {
                dvui.label(@src(), "{s} · PID {d}", .{ svc, p.pid }, .{ .color_text = common.dim_text, .font = common.fontCaption() });
            } else {
                dvui.label(@src(), "PID {d}", .{p.pid}, .{ .color_text = common.dim_text, .font = common.fontCaption() });
            }
        }
    }

    {
        var tiles = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal, .padding = .{ .x = 0, .y = 6, .w = 0, .h = 6 } });
        defer tiles.deinit();
        if (p.isIcmp()) {
            statTile(0, "ECHO RATE", common.fmtMsgRate(&buf1, p.down_bps), common.down_color);
            statTile(1, "SESSION", common.fmtMsgTotal(&buf2, p.down_total), null);
        } else {
            statTile(0, "DOWN", common.fmtSpeed(&buf1, p.down_bps), common.down_color);
            statTile(1, "UP", common.fmtSpeed(&buf2, p.up_bps), common.up_color);
            var buf3: [48]u8 = undefined;
            var buf4: [48]u8 = undefined;
            statTile(2, "DOWN SESSION", common.fmtBytes(&buf3, p.down_total), null);
            statTile(3, "UP SESSION", common.fmtBytes(&buf4, p.up_total), null);
        }
    }

    dvui.label(@src(), "FLOWS ({d})", .{p.flows.len}, .{ .color_text = common.dim_text, .font = common.fontCaptionHeading() });

    {
        var grid: dvui.GridWidget = undefined;
        grid.init(@src(), .{ .rows = p.flows.len }, .{ .expand = .both });
        defer grid.deinit();

        const titles = [_][]const u8{ "Proto", "Remote", "Down", "Up", "Down total", "Up total" };
        for (titles, 0..) |t, col| {
            const cell = grid.colHeader(col, .{});
            defer cell.deinit();
            const w: f32 = if (col == 1) 320 else if (col >= 2) 92 else 0;
            dvui.label(@src(), "{s}", .{t}, .{ .color_text = common.dim_text, .min_size_content = .{ .w = w } });
        }

        var buf: [48]u8 = undefined;
        for (p.flows, 0..) |*f, row| {
            {
                var cell = grid.cell(.{ .col = 0, .row = row }, .{});
                defer cell.deinit();
                common.protoBadge(f.proto, .{});
            }
            {
                var cell = grid.cell(.{ .col = 1, .row = row }, .{});
                defer cell.deinit();
                var rbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
                defer rbox.deinit();
                if (f.hostname) |h| {
                    dvui.label(@src(), "{s}", .{h}, .{ .gravity_y = 0.5, .color_text = if (f.reverse_fallback) common.dim_text else null });
                    dvui.label(@src(), "{s}", .{f.endpoint}, .{ .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
                } else {
                    dvui.label(@src(), "{s}", .{f.endpoint}, .{ .gravity_y = 0.5 });
                }
            }
            if (f.proto == .icmp) {
                flowNumCell(&grid, 2, row, common.fmtMsgRate(&buf, f.down_bps), null);
                flowNumCell(&grid, 3, row, "—", null);
                flowNumCell(&grid, 4, row, common.fmtMsgTotal(&buf, f.down_total), null);
                flowNumCell(&grid, 5, row, "—", null);
            } else {
                flowNumCell(&grid, 2, row, common.fmtSpeed(&buf, f.down_bps), common.speedFill(f.down_bps, false));
                flowNumCell(&grid, 3, row, common.fmtSpeed(&buf, f.up_bps), common.speedFill(f.up_bps, true));
                flowNumCell(&grid, 4, row, common.fmtBytes(&buf, f.down_total), null);
                flowNumCell(&grid, 5, row, common.fmtBytes(&buf, f.up_total), null);
            }
        }
    }
}

fn statTile(id: usize, title: []const u8, value: []const u8, accent: ?dvui.Color) void {
    var tile = dvui.box(@src(), .{ .dir = .vertical }, .{
        .id_extra = id,
        .background = true,
        .style = .control,
        .corners = .all(8),
        .margin = .{ .x = 0, .y = 0, .w = 8, .h = 0 },
        .padding = .{ .x = 10, .y = 6, .w = 10, .h = 6 },
        .min_size_content = .{ .w = 120 },
    });
    defer tile.deinit();
    dvui.label(@src(), "{s}", .{title}, .{ .color_text = common.dim_text, .font = common.fontCaption() });
    dvui.label(@src(), "{s}", .{value}, .{ .font = common.fontTitle(), .color_text = accent });
}

fn flowNumCell(grid: *dvui.GridWidget, col: usize, row: usize, text: []const u8, fill: ?dvui.Color) void {
    var opts: dvui.Options = .{};
    if (fill) |c| {
        opts.color_fill = c;
        opts.background = true;
    }
    var cell = grid.cell(.{ .col = col, .row = row }, opts);
    defer cell.deinit();
    dvui.label(@src(), "{s}", .{text}, .{
        .expand = .horizontal,
        .gravity_x = 1.0,
        .color_text = if (std.mem.eql(u8, text, "—")) common.dim_text else null,
    });
}
