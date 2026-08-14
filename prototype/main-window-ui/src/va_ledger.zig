//! PROTOTYPE — Variant A "Ledger": one dense sortable table, flows expand inline
//! beneath their Process Row (NetLimiter-style information hierarchy).
const std = @import("std");
const dvui = @import("dvui");
const data = @import("data.zig");
const state = @import("state.zig");
const common = @import("common.zig");

const DispRow = struct {
    proc: *data.ProcRow,
    flow: ?*data.Flow, // null = process row
};

var disp_buf: [96]DispRow = undefined;

fn buildDisplayRows() []DispRow {
    var n: usize = 0;
    for (data.procs) |*p| {
        disp_buf[n] = .{ .proc = p, .flow = null };
        n += 1;
        if (p.expanded) {
            for (p.flows) |*f| {
                disp_buf[n] = .{ .proc = p, .flow = f };
                n += 1;
            }
        }
    }
    return disp_buf[0..n];
}

fn applySort(field: state.SortField, dir: dvui.GridWidget.SortDirection) void {
    state.sort_field = field;
    state.sort_descending = (dir == .descending);
}

pub fn frame() void {
    state.sortProcs();
    const rows = buildDisplayRows();

    var vbox = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .both });
    defer vbox.deinit();

    {
        var grid: dvui.GridWidget = undefined;
        grid.init(@src(), .{ .rows = rows.len }, .{ .expand = .both });
        defer grid.deinit();

        const hdr_opts: dvui.Options = .{};
        {
            const cell = grid.colHeader(0, hdr_opts);
            defer cell.deinit();
            if (cell.headerSortable("Process", .{ .min_size_content = .{ .w = 330 } })) |dir| applySort(.name, dir);
        }
        {
            const cell = grid.colHeader(1, hdr_opts);
            defer cell.deinit();
            dvui.label(@src(), "PID", .{}, .{ .color_text = common.dim_text });
        }
        {
            const cell = grid.colHeader(2, hdr_opts);
            defer cell.deinit();
            if (cell.headerSortable("Down", .{ .min_size_content = .{ .w = 96 } })) |dir| applySort(.down, dir);
        }
        {
            const cell = grid.colHeader(3, hdr_opts);
            defer cell.deinit();
            if (cell.headerSortable("Up", .{ .min_size_content = .{ .w = 96 } })) |dir| applySort(.up, dir);
        }
        {
            const cell = grid.colHeader(4, hdr_opts);
            defer cell.deinit();
            if (cell.headerSortable("Down total", .{ .min_size_content = .{ .w = 90 } })) |dir| applySort(.down_total, dir);
        }
        {
            const cell = grid.colHeader(5, hdr_opts);
            defer cell.deinit();
            if (cell.headerSortable("Up total", .{ .min_size_content = .{ .w = 90 } })) |dir| applySort(.up_total, dir);
        }

        // click a process row -> toggle its flows
        if (grid.cellActivated()) |ca| {
            if (ca.cell.row < rows.len and rows[ca.cell.row].flow == null) {
                rows[ca.cell.row].proc.expanded = !rows[ca.cell.row].proc.expanded;
            }
        }

        const hovered = grid.cellHovered();

        for (rows, 0..) |dr, row| {
            const p = dr.proc;
            var row_opts: dvui.Options = .{};
            if (hovered) |hc| {
                if (hc.row == row) {
                    row_opts.color_fill = dvui.themeGet().color(.control, .fill_hover);
                    row_opts.background = true;
                }
            }
            if (dr.flow) |f| {
                flowRow(&grid, row, p, f, row_opts);
            } else {
                procRow(&grid, row, p, row_opts);
            }
        }
    }

    statusBar();
}

fn procRow(grid: *dvui.GridWidget, row: usize, p: *data.ProcRow, row_opts: dvui.Options) void {
    var buf: [48]u8 = undefined;
    {
        var cell = grid.cell(.{ .col = 0, .row = row }, row_opts);
        defer cell.deinit();
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hbox.deinit();

        const tvg = if (p.expanded) dvui.entypo.triangle_down else dvui.entypo.triangle_right;
        dvui.icon(@src(), "exp", tvg, .{}, .{ .gravity_y = 0.5, .min_size_content = .{ .w = 10, .h = 10 }, .color_text = common.dim_text });
        common.procBadge(p, .{});
        dvui.label(@src(), "{s}", .{p.name}, .{ .gravity_y = 0.5 });
        if (p.service) |svc| {
            dvui.label(@src(), "· {s}", .{svc}, .{ .gravity_y = 0.5, .color_text = common.dim_text });
        }
        dvui.label(@src(), "({d})", .{p.flows.len}, .{ .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
    }
    {
        var cell = grid.cell(.{ .col = 1, .row = row }, row_opts);
        defer cell.deinit();
        dvui.label(@src(), "{d}", .{p.pid}, .{ .color_text = common.dim_text, .expand = .horizontal, .gravity_x = 1.0 });
    }
    if (p.isIcmp()) {
        speedCell(grid, 2, row, common.fmtMsgRate(&buf, p.down_bps), null, row_opts);
        speedCell(grid, 3, row, "—", null, row_opts);
        speedCell(grid, 4, row, common.fmtMsgTotal(&buf, p.down_total), null, row_opts);
        speedCell(grid, 5, row, "—", null, row_opts);
    } else {
        speedCell(grid, 2, row, common.fmtSpeed(&buf, p.down_bps), common.speedFill(p.down_bps, false), row_opts);
        speedCell(grid, 3, row, common.fmtSpeed(&buf, p.up_bps), common.speedFill(p.up_bps, true), row_opts);
        speedCell(grid, 4, row, common.fmtBytes(&buf, p.down_total), null, row_opts);
        speedCell(grid, 5, row, common.fmtBytes(&buf, p.up_total), null, row_opts);
    }
}

fn flowRow(grid: *dvui.GridWidget, row: usize, p: *data.ProcRow, f: *data.Flow, row_opts: dvui.Options) void {
    var buf: [48]u8 = undefined;
    _ = p;
    {
        var cell = grid.cell(.{ .col = 0, .row = row }, row_opts);
        defer cell.deinit();
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
        defer hbox.deinit();

        _ = dvui.spacer(@src(), .{ .min_size_content = .{ .w = 26 } });
        common.protoBadge(f.proto, .{});
        if (f.hostname) |h| {
            dvui.label(@src(), "{s}", .{h}, .{
                .gravity_y = 0.5,
                .color_text = if (f.reverse_fallback) common.dim_text else null,
            });
            dvui.label(@src(), "{s}", .{f.endpoint}, .{ .gravity_y = 0.5, .color_text = common.dim_text, .font = common.fontCaption() });
        } else {
            dvui.label(@src(), "{s}", .{f.endpoint}, .{ .gravity_y = 0.5 });
        }
    }
    {
        var cell = grid.cell(.{ .col = 1, .row = row }, row_opts);
        defer cell.deinit();
        dvui.label(@src(), " ", .{}, .{});
    }
    if (f.proto == .icmp) {
        speedCell(grid, 2, row, common.fmtMsgRate(&buf, f.down_bps), null, row_opts);
        speedCell(grid, 3, row, "—", null, row_opts);
        speedCell(grid, 4, row, common.fmtMsgTotal(&buf, f.down_total), null, row_opts);
        speedCell(grid, 5, row, "—", null, row_opts);
    } else {
        speedCell(grid, 2, row, common.fmtSpeed(&buf, f.down_bps), common.speedFill(f.down_bps, false), row_opts);
        speedCell(grid, 3, row, common.fmtSpeed(&buf, f.up_bps), common.speedFill(f.up_bps, true), row_opts);
        speedCell(grid, 4, row, common.fmtBytes(&buf, f.down_total), null, row_opts);
        speedCell(grid, 5, row, common.fmtBytes(&buf, f.up_total), null, row_opts);
    }
}

fn speedCell(grid: *dvui.GridWidget, col: usize, row: usize, text: []const u8, fill: ?dvui.Color, row_opts: dvui.Options) void {
    var opts = row_opts;
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

fn statusBar() void {
    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;
    var buf3: [48]u8 = undefined;
    var buf4: [48]u8 = undefined;

    var bar = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .expand = .horizontal,
        .background = true,
        .style = .control,
        .padding = .{ .x = 8, .y = 3, .w = 8, .h = 3 },
    });
    defer bar.deinit();

    dvui.label(@src(), "{d} active flows", .{data.flow_count}, .{ .color_text = common.dim_text, .font = common.fontCaption(), .gravity_y = 0.5 });
    dvui.label(@src(), "·  Down {s}  Up {s}", .{
        common.fmtSpeed(&buf1, data.global_down_bps),
        common.fmtSpeed(&buf2, data.global_up_bps),
    }, .{ .color_text = common.dim_text, .font = common.fontCaption(), .gravity_y = 0.5 });
    dvui.label(@src(), "·  session {s} down / {s} up", .{
        common.fmtBytes(&buf3, data.global_down_total),
        common.fmtBytes(&buf4, data.global_up_total),
    }, .{ .color_text = common.dim_text, .font = common.fontCaption(), .gravity_y = 0.5 });
    dvui.label(@src(), "FAKE DATA", .{}, .{
        .gravity_x = 1.0,
        .gravity_y = 0.5,
        .color_text = .{ .r = 0xd8, .g = 0x60, .b = 0x60 },
        .font = common.fontCaptionHeading(),
    });
}
