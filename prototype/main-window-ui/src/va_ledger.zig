//! PROTOTYPE — Variant A "Ledger": NetLimiter-style. One dense sortable table with flows
//! expanding inline, plus a right-docked Info View driven by the selected row (process or
//! flow) with a Tools section stubbed for future per-address extensions (traceroute, MTR…).
const std = @import("std");
const dvui = @import("dvui");
const data = @import("data.zig");
const state = @import("state.zig");
const common = @import("common.zig");

const accent: dvui.Color = .{ .r = 0x4d, .g = 0xa8, .b = 0xe8 }; // info-view header / links
const sel_fill: dvui.Color = .{ .r = 0x26, .g = 0x4f, .b = 0x78 }; // selected row

const DispRow = struct {
    proc: *data.ProcRow,
    flow: ?*data.Flow, // null = process row
    flow_idx: ?usize,
};

var disp_buf: [96]DispRow = undefined;

fn buildDisplayRows() []DispRow {
    var n: usize = 0;
    for (data.procs) |*p| {
        disp_buf[n] = .{ .proc = p, .flow = null, .flow_idx = null };
        n += 1;
        if (p.expanded) {
            for (p.flows, 0..) |*f, fi| {
                disp_buf[n] = .{ .proc = p, .flow = f, .flow_idx = fi };
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
        var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .both });
        defer hbox.deinit();

        tablePane(rows);
        _ = dvui.separator(@src(), .{ .expand = .vertical });
        infoView();
    }

    statusBar();
}

fn tablePane(rows: []DispRow) void {
    var pane = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .both });
    defer pane.deinit();

    var grid: dvui.GridWidget = undefined;
    grid.init(@src(), .{ .rows = rows.len }, .{ .expand = .both });
    defer grid.deinit();

    const hdr_opts: dvui.Options = .{};
    {
        const cell = grid.colHeader(0, hdr_opts);
        defer cell.deinit();
        if (cell.headerSortable("Process", .{ .min_size_content = .{ .w = 300 } })) |dir| applySort(.name, dir);
    }
    {
        const cell = grid.colHeader(1, hdr_opts);
        defer cell.deinit();
        dvui.label(@src(), "PID", .{}, .{ .color_text = common.dim_text });
    }
    {
        const cell = grid.colHeader(2, hdr_opts);
        defer cell.deinit();
        if (cell.headerSortable("Down", .{ .min_size_content = .{ .w = 88 } })) |dir| applySort(.down, dir);
    }
    {
        const cell = grid.colHeader(3, hdr_opts);
        defer cell.deinit();
        if (cell.headerSortable("Up", .{ .min_size_content = .{ .w = 88 } })) |dir| applySort(.up, dir);
    }
    {
        const cell = grid.colHeader(4, hdr_opts);
        defer cell.deinit();
        if (cell.headerSortable("Down total", .{ .min_size_content = .{ .w = 84 } })) |dir| applySort(.down_total, dir);
    }
    {
        const cell = grid.colHeader(5, hdr_opts);
        defer cell.deinit();
        if (cell.headerSortable("Up total", .{ .min_size_content = .{ .w = 84 } })) |dir| applySort(.up_total, dir);
    }

    // click: select the row's process/flow; a process-row click also toggles its flows
    if (grid.cellActivated()) |ca| {
        if (ca.cell.row < rows.len) {
            const dr = rows[ca.cell.row];
            state.selected = .{ .pid = dr.proc.pid, .flow_idx = dr.flow_idx };
            if (dr.flow == null) dr.proc.expanded = !dr.proc.expanded;
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
        if (state.selected) |sel| {
            if (sel.pid == p.pid and std.meta.eql(sel.flow_idx, dr.flow_idx)) {
                row_opts.color_fill = sel_fill;
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
        // keep the selection/hover tint visible on non-colored cells only
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

// ---------- Info View (NetLimiter-style right dock) ----------

fn infoView() void {
    var panel = dvui.box(@src(), .{ .dir = .vertical }, .{
        .expand = .vertical,
        .min_size_content = .{ .w = 300 },
        .max_size_content = .width(300),
        .background = true,
        .style = .window,
        .padding = .{ .x = 10, .y = 6, .w = 10, .h = 6 },
    });
    defer panel.deinit();

    dvui.label(@src(), "INFO VIEW", .{}, .{ .color_text = common.dim_text, .font = common.fontCaptionHeading() });

    var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both });
    defer scroll.deinit();

    const sel = state.selected orelse {
        dvui.label(@src(), "Select a process or flow", .{}, .{ .color_text = common.dim_text, .gravity_x = 0.5, .padding = .{ .x = 0, .y = 30, .w = 0, .h = 0 } });
        return;
    };
    const p = state.findProc(sel.pid) orelse return;

    if (sel.flow_idx) |fi| {
        if (fi < p.flows.len) {
            flowInfo(p, &p.flows[fi]);
            return;
        }
    }
    procInfo(p);
}

fn procInfo(p: *data.ProcRow) void {
    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;

    dvui.label(@src(), "Process", .{}, .{ .color_text = accent, .font = common.fontTitle() });
    dvui.label(@src(), "{s}", .{p.name}, .{ .font = common.fontCaptionHeading() });
    if (p.service) |svc| {
        dvui.label(@src(), "{s}", .{svc}, .{ .color_text = common.dim_text, .font = common.fontCaption() });
    }

    if (dvui.expander(@src(), "Process properties", .{ .default_expanded = true }, .{ .expand = .horizontal, .font = common.fontCaptionHeading() })) {
        var sec = section(@src());
        defer sec.deinit();
        kv(0, "Name", p.name, false);
        var pidbuf: [16]u8 = undefined;
        kv(1, "PID", std.fmt.bufPrint(&pidbuf, "{d}", .{p.pid}) catch "?", false);
        if (p.service) |svc| kv(2, "Service", svc, false);
        kv(3, "Path", p.path, true);
        var fbuf: [16]u8 = undefined;
        kv(4, "Flows", std.fmt.bufPrint(&fbuf, "{d}", .{p.flows.len}) catch "?", false);
    }

    if (dvui.expander(@src(), "Activity", .{ .default_expanded = true }, .{ .expand = .horizontal, .font = common.fontCaptionHeading() })) {
        var sec = section(@src());
        defer sec.deinit();
        if (p.isIcmp()) {
            kv(0, "Echo rate", common.fmtMsgRate(&buf1, p.down_bps), false);
            kv(1, "Session", common.fmtMsgTotal(&buf2, p.down_total), false);
        } else {
            kv(0, "Down rate", common.fmtSpeed(&buf1, p.down_bps), false);
            kv(1, "Up rate", common.fmtSpeed(&buf2, p.up_bps), false);
            var buf3: [48]u8 = undefined;
            var buf4: [48]u8 = undefined;
            kv(2, "Down session", common.fmtBytes(&buf3, p.down_total), false);
            kv(3, "Up session", common.fmtBytes(&buf4, p.up_total), false);
        }
    }

    if (dvui.expander(@src(), "Tools", .{ .default_expanded = true }, .{ .expand = .horizontal, .font = common.fontCaptionHeading() })) {
        var sec = section(@src());
        defer sec.deinit();
        toolLink(0, "Open file location");
        toolLink(1, "Copy path");
        extensionNote();
    }
}

fn flowInfo(p: *data.ProcRow, f: *data.Flow) void {
    var buf1: [48]u8 = undefined;
    var buf2: [48]u8 = undefined;

    dvui.label(@src(), "Flow", .{}, .{ .color_text = accent, .font = common.fontTitle() });
    if (f.hostname) |h| {
        dvui.label(@src(), "{s}", .{h}, .{ .font = common.fontCaptionHeading(), .color_text = if (f.reverse_fallback) common.dim_text else null });
    } else {
        dvui.label(@src(), "{s}", .{f.endpoint}, .{ .font = common.fontCaptionHeading() });
    }
    dvui.label(@src(), "{s} · {s}", .{ p.name, if (p.service) |svc| svc else "" }, .{ .color_text = common.dim_text, .font = common.fontCaption() });

    if (dvui.expander(@src(), "Flow properties", .{ .default_expanded = true }, .{ .expand = .horizontal, .font = common.fontCaptionHeading() })) {
        var sec = section(@src());
        defer sec.deinit();
        kv(0, "Protocol", common.protoLabel(f.proto), false);
        kv(1, "Local", f.local, false);
        kv(2, "Remote", f.endpoint, false);
        if (f.hostname) |h| {
            kv(3, "Remote name", h, f.reverse_fallback);
            if (f.reverse_fallback) kv(4, "", "(reverse lookup)", true);
        } else {
            kv(3, "Remote name", "Unresolved", true);
        }
        kv(5, "Country", if (f.country) |c| c else "—", f.country == null);
    }

    if (dvui.expander(@src(), "Activity", .{ .default_expanded = true }, .{ .expand = .horizontal, .font = common.fontCaptionHeading() })) {
        var sec = section(@src());
        defer sec.deinit();
        if (f.proto == .icmp) {
            kv(0, "Echo rate", common.fmtMsgRate(&buf1, f.down_bps), false);
            kv(1, "Session", common.fmtMsgTotal(&buf2, f.down_total), false);
        } else {
            kv(0, "Down rate", common.fmtSpeed(&buf1, f.down_bps), false);
            kv(1, "Up rate", common.fmtSpeed(&buf2, f.up_bps), false);
            var buf3: [48]u8 = undefined;
            var buf4: [48]u8 = undefined;
            kv(2, "Down session", common.fmtBytes(&buf3, f.down_total), false);
            kv(3, "Up session", common.fmtBytes(&buf4, f.up_total), false);
        }
    }

    if (dvui.expander(@src(), "Tools", .{ .default_expanded = true }, .{ .expand = .horizontal, .font = common.fontCaptionHeading() })) {
        var sec = section(@src());
        defer sec.deinit();
        toolLink(0, "Traceroute");
        toolLink(1, "MTR");
        toolLink(2, "WHOIS");
        toolLink(3, "Copy remote address");
        extensionNote();
    }
}

fn section(src: std.builtin.SourceLocation) *dvui.BoxWidget {
    return dvui.box(src, .{ .dir = .vertical }, .{
        .expand = .horizontal,
        .margin = .{ .x = 12, .y = 2, .w = 0, .h = 6 },
    });
}

fn kv(id: usize, key: []const u8, value: []const u8, dim_value: bool) void {
    var row = dvui.box(@src(), .{ .dir = .horizontal }, .{ .id_extra = id, .expand = .horizontal });
    defer row.deinit();
    dvui.label(@src(), "{s}", .{key}, .{
        .color_text = common.dim_text,
        .font = common.fontCaption(),
        .min_size_content = .{ .w = 88 },
        .gravity_y = 0.5,
    });
    dvui.label(@src(), "{s}", .{value}, .{
        .font = common.fontCaption(),
        .gravity_y = 0.5,
        .color_text = if (dim_value) common.dim_text else null,
    });
}

fn toolLink(id: usize, name: []const u8) void {
    if (dvui.labelClick(@src(), "{s}", .{name}, .{}, .{
        .id_extra = id,
        .color_text = accent,
        .font = common.fontCaption(),
        .padding = .{ .x = 0, .y = 1, .w = 0, .h = 1 },
    })) {
        dvui.toast(@src(), .{ .id_extra = id, .message = "Extension point — not in v1.\nWould run against this address." });
    }
}

fn extensionNote() void {
    dvui.label(@src(), "extension points (v2+)", .{}, .{ .color_text = common.dim_text, .font = common.fontCaption(), .padding = .{ .x = 0, .y = 3, .w = 0, .h = 0 } });
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
