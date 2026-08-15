//! The Ledger: one dense sortable table of Process Rows with their Flows
//! expanding inline beneath them, a right-docked Info View driven by the
//! selection, and a status bar under both. This is the layout the UI prototype
//! settled on and issue #10 locked.
//!
//! The frame reads a Snapshot it does not own and allocates nothing per cell —
//! every number is formatted into a stack buffer. What it *does* own is the
//! row order, which rows are open and what is selected, and all three survive
//! across frames, across Snapshots, and across the teardown-recreate cycle:
//! they live here, not in the dvui context that gets destroyed when the window
//! closes.

const std = @import("std");
const dvui = @import("dvui");
const engine = @import("engine");

const info_view = @import("info_view.zig");
const style = @import("style.zig");
const view = @import("view.zig");

const snapshot = engine.snapshot;
const format = view.format;
const order = view.order;

/// The table, declared once (spec issue #24: Process, PID, Down, Up, Down
/// total, Up total). Position in this list *is* the column index, so the
/// header row, the cells, and the sort round-trip cannot drift apart.
const columns = [_]Column{
    .{ .sort = .name, .label = "Process", .min_width = 260 },
    // All sortable except PID (locked layout, issue #10).
    .{ .sort = null, .label = "PID", .min_width = 60 },
    .{ .sort = .down, .label = "Down", .min_width = 88 },
    .{ .sort = .up, .label = "Up", .min_width = 88 },
    .{ .sort = .down_total, .label = "Down total", .min_width = 92 },
    .{ .sort = .up_total, .label = "Up total", .min_width = 92 },
};

const Column = struct {
    /// What clicking this column's header orders the table by, or null for the
    /// one column that orders nothing.
    sort: ?order.Field,
    label: []const u8,
    min_width: f32,

    /// Which way a column sorts when it is reached for the first time: the way
    /// that column is worth reaching for. Busiest first for anything numeric,
    /// A–Z for a name.
    fn firstClick(field: order.Field) order.Direction {
        return switch (field) {
            .name => .ascending,
            .down, .up, .down_total, .up_total => .descending,
        };
    }
};

fn columnOf(sort: ?order.Field) usize {
    for (columns, 0..) |c, i| {
        if (std.meta.eql(c.sort, sort)) return i;
    }
    unreachable; // every Field has a column, by the table above
}

const col_process = columnOf(.name);
/// The column that sorts by nothing — PID, and only PID.
const col_pid = columnOf(null);
const col_down = columnOf(.down);
const col_up = columnOf(.up);
const col_down_total = columnOf(.down_total);
const col_up_total = columnOf(.up_total);

/// How far a Flow's line is indented under its Process Row — past the
/// chevron and the badge, so the protocol tags line up in a column of their
/// own.
const flow_indent = 26;

pub const Ledger = struct {
    ordering: order.Ordering = .{},
    table: view.table.Table = .{},
    info: info_view.InfoView = .{},

    pub fn deinit(self: *Ledger, gpa: std.mem.Allocator) void {
        self.ordering.deinit(gpa);
        self.table.deinit(gpa);
    }

    /// One frame. `now_ms` is the app's monotonic clock — the beat the row
    /// order re-sorts on, not anything the Snapshot carries.
    pub fn frame(
        self: *Ledger,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        now_ms: u64,
    ) void {
        var vbox = dvui.box(@src(), .{ .dir = .vertical }, .{ .expand = .both });
        defer vbox.deinit();

        {
            var split = dvui.box(@src(), .{ .dir = .horizontal }, .{
                .expand = .both,
                // Like the grid below, this demands no height of its own —
                // otherwise it reports what it was given as its minimum and
                // pushes the status bar off the window.
                .max_size_content = .height(0),
            });
            defer split.deinit();

            self.tablePane(gpa, snap, now_ms);
            _ = dvui.separator(@src(), .{ .expand = .vertical });
            // Drawn after the table, so it shows the selection this frame's
            // click just made rather than the one before it.
            self.info.frame(snap, self.table.inspected());
        }

        statusBar(snap);
    }

    fn tablePane(
        self: *Ledger,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        now_ms: u64,
    ) void {
        const display = self.ordering.display(gpa, snap.rows, now_ms);
        const lines = self.table.build(gpa, snap, display);

        var grid: dvui.GridWidget = undefined;
        grid.init(@src(), .{ .rows = lines.len }, .{
            .expand = .both,
            // The table demands no height of its own — it takes whatever is
            // left. Without this it reports the height it was given as its
            // minimum, which is self-fulfilling: the box then has nothing
            // left to place the status bar in and pushes it off the window.
            .max_size_content = .height(0),
        });
        defer grid.deinit();

        // The Ordering is the source of truth; the header only displays it and
        // reports clicks. Writing it back each frame is also what keeps the
        // chevron honest after a teardown-recreate cycle, which takes the
        // grid's own remembered sort state with it.
        grid.sort_col = columnOf(self.ordering.field);
        grid.sort_dir = switch (self.ordering.direction) {
            .ascending => .ascending,
            .descending => .descending,
        };

        for (columns, 0..) |column, col| self.header(&grid, col, column);

        // Only the rows on screen are emitted: the machine has hundreds of
        // processes and the window shows tens of them. This also fixes where
        // the grid thinks the visible rows start, which is what turns a click
        // position back into a row — so it comes before reading clicks.
        const first, const last = grid.rowsVisible();

        // A click resolves against the lines this frame is about to draw, and
        // those are in the order the last beat froze — which is the whole
        // reason the order is frozen (order.zig). Any expansion it toggles
        // shows on the next frame, so the line the user aimed at is the line
        // that was hit.
        if (grid.cellActivated()) |activated| {
            if (activated.cell.row < lines.len)
                self.table.click(gpa, snap, lines[activated.cell.row]);
        }
        const hovered = grid.cellHovered();

        for (first..last) |row| {
            if (row >= lines.len) break;
            self.cells(&grid, row, lines[row], snap, hovered);
        }
    }

    fn header(self: *Ledger, grid: *dvui.GridWidget, col: usize, column: Column) void {
        const cell = grid.colHeader(col, .{});
        defer cell.deinit();
        const field = column.sort orelse {
            // A column that orders nothing gets a plain heading, so it never
            // offers a sort it will not perform.
            dvui.label(@src(), "{s}", .{column.label}, .{
                .min_size_content = .{ .w = column.min_width },
                .gravity_x = 0.5,
                .color_text = style.dim,
            });
            return;
        };
        const clicked = cell.headerSortable(column.label, .{
            .min_size_content = .{ .w = column.min_width },
        }) orelse return;
        // Clicking the column you are already on flips it, which is what the
        // widget reports; reaching a new one starts it where that column is
        // worth starting.
        const direction: order.Direction = if (self.ordering.field != field)
            Column.firstClick(field)
        else switch (clicked) {
            .ascending => .ascending,
            .descending, .unsorted => .descending,
        };
        self.ordering.sortBy(field, direction);
    }

    /// One line, Process Row or Flow. The two decisions that belong to the
    /// whole line — what fills it and what colour its text takes — are made
    /// here, once, and carried into every cell by the Pen.
    fn cells(
        self: *Ledger,
        grid: *dvui.GridWidget,
        row: usize,
        line: view.table.Line,
        snap: *const snapshot.Snapshot,
        hovered: ?dvui.GridWidget.Cell,
    ) void {
        var fill: ?dvui.Color = null;
        if (hovered) |cell| {
            if (cell.row == row) fill = dvui.themeGet().color(.control, .fill_hover);
        }
        // Selection wins over hover: the line you picked stays picked while
        // the cursor wanders over the others.
        if (self.table.isSelected(line)) fill = style.selection;

        const r = snap.rows[line.row];
        if (line.flow) |flow_idx| {
            const f = r.flows[flow_idx];
            // A Lingering Flow is a closed conversation still on screen
            // (CONTEXT.md "Linger") — dimmed whole, the way an exited row is.
            const pen: Pen = .{
                .grid = grid,
                .row = row,
                .fill = fill,
                .text = if (f.lingering) style.dim else null,
            };
            flowCells(pen, f);
        } else {
            // Exited rows stay all session with their totals intact, dimmed
            // (CONTEXT.md "Process Row"). Dimming the whole row is what
            // separates "this process is quiet" from "this process is gone".
            const pen: Pen = .{
                .grid = grid,
                .row = row,
                .fill = fill,
                .text = if (r.exited) style.dim else null,
            };
            processCells(pen, r, self.table.isExpanded(r));
        }
    }
};

/// What one line's cells are drawn with. The grid and the line index are the
/// same for every cell of a line, and so are the two colours — so they travel
/// together rather than through seven-parameter signatures.
const Pen = struct {
    grid: *dvui.GridWidget,
    row: usize,
    /// The line's own background: the selection accent, the hover tint, or
    /// nothing at all.
    fill: ?dvui.Color,
    /// Set when the whole line is dimmed — an exited Process Row, a Lingering
    /// Flow; null leaves the text in the theme's own colour.
    text: ?dvui.Color,

    /// One cell, filled the way the line is. Caller deinits.
    fn cell(self: Pen, col: usize) *dvui.GridWidget.CellWidget {
        return self.filledCell(col, self.fill);
    }

    fn filledCell(self: Pen, col: usize, fill: ?dvui.Color) *dvui.GridWidget.CellWidget {
        return self.grid.cell(.{ .col = col, .row = self.row }, .{
            .color_fill = fill,
            .background = fill != null,
        });
    }

    /// A speed cell, tinted by how busy it is: green down, amber amber up,
    /// log-scaled (locked layout, issue #10). The tint goes *over* whatever
    /// fills the line, so a selected row stays visibly selected under its own
    /// activity instead of losing the accent on exactly the cells being read.
    fn rate(self: Pen, col: usize, bytes_per_s: u64, dir: format.Direction) void {
        const tint = style.activityFill(bytes_per_s, dir);
        var cel = self.filledCell(col, if (tint) |t| style.tinted(self.fill, t) else self.fill);
        defer cel.deinit();

        var buf: [format.rate_buf_len]u8 = undefined;
        dvui.label(@src(), "{s}", .{format.rate(&buf, bytes_per_s)}, numberOpts(
            if (bytes_per_s == 0) style.dim else self.text,
        ));
    }

    /// An In-session Totals cell, in whichever unit the line actually has:
    /// bytes, or ICMP messages (CONTEXT.md "ICMP Message Count").
    fn volume(self: Pen, col: usize, v: format.Volume) void {
        var cel = self.cell(col);
        defer cel.deinit();
        // A cell with nothing in it is already a dash; dimming it too keeps
        // the eye on the rows that are actually moving.
        var buf: [format.msgs_buf_len]u8 = undefined;
        dvui.label(@src(), "{s}", .{format.volume(&buf, v)}, numberOpts(
            if (format.isIdle(v)) style.dim else self.text,
        ));
    }
};

fn processCells(pen: Pen, r: snapshot.Row, expanded: bool) void {
    processCell(pen, r, expanded);
    {
        var cell = pen.cell(col_pid);
        defer cell.deinit();
        // The Evicted-processes Row owns no PID — it is where attribution
        // stops (CONTEXT.md), and a number there would be a lie.
        if (r.evicted_processes)
            dvui.label(@src(), "{s}", .{format.idle}, numberOpts(style.dim))
        else
            dvui.label(@src(), "{d}", .{r.pid}, numberOpts(pen.text orelse style.dim));
    }

    pen.rate(col_down, r.recv_rate, .down);
    pen.rate(col_up, r.sent_rate, .up);
    pen.volume(col_down_total, format.rowVolume(r, .down));
    pen.volume(col_up_total, format.rowVolume(r, .up));
}

fn processCell(pen: Pen, r: snapshot.Row, expanded: bool) void {
    var cell = pen.cell(col_process);
    defer cell.deinit();
    var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
    defer hbox.deinit();

    // A row with no Flows has nothing to open, and says so by not offering.
    // The space stays either way, so the names stay in one column.
    if (r.flows.len > 0)
        dvui.icon(@src(), "expand", if (expanded)
            dvui.entypo.triangle_down
        else
            dvui.entypo.triangle_right, .{}, .{
            .gravity_y = 0.5,
            .min_size_content = .{ .w = 10, .h = 10 },
            .color_text = style.dim,
        })
    else
        _ = dvui.spacer(@src(), .{ .min_size_content = .{ .w = 10 } });

    processBadge(r);
    dvui.label(@src(), "{s}", .{format.processName(r.name)}, .{
        .gravity_y = 0.5,
        .color_text = pen.text,
    });
    // Service Attribution (CONTEXT.md): one service means the row *is* that
    // service; several mean a shared host, and the honest fallback names the
    // count rather than picking one.
    if (r.services.len == 1) {
        dvui.label(@src(), "· {s}", .{r.services[0]}, .{ .gravity_y = 0.5, .color_text = style.dim });
    } else if (r.services.len > 1) {
        dvui.label(@src(), "· {d} services", .{r.services.len}, .{ .gravity_y = 0.5, .color_text = style.dim });
    }
    if (r.flows.len > 0) {
        dvui.label(@src(), "({d})", .{r.flows.len}, .{
            .gravity_y = 0.5,
            .color_text = style.dim,
            .font = style.caption(),
        });
    }
    if (r.exited and !r.evicted_processes)
        dvui.label(@src(), "(exited)", .{}, .{ .gravity_y = 0.5, .color_text = style.dim });
}

fn flowCells(pen: Pen, f: snapshot.Flow) void {
    flowCell(pen, f);
    {
        // A Flow has no PID of its own: it belongs to the row above it. The
        // cell is still drawn, so the line's fill runs the width of the table.
        var cell = pen.cell(col_pid);
        defer cell.deinit();
        _ = dvui.spacer(@src(), .{ .expand = .horizontal });
    }

    // ICMP publishes no speeds — there are no byte sizes to build one from —
    // so these come out as the dash and no cell fill, which is what a Flow
    // that moves messages instead of bytes honestly looks like here.
    pen.rate(col_down, f.recv_rate, .down);
    pen.rate(col_up, f.sent_rate, .up);
    pen.volume(col_down_total, format.flowVolume(f, .down));
    pen.volume(col_up_total, format.flowVolume(f, .up));
}

fn flowCell(pen: Pen, f: snapshot.Flow) void {
    var cell = pen.cell(col_process);
    defer cell.deinit();
    var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
    defer hbox.deinit();

    _ = dvui.spacer(@src(), .{ .min_size_content = .{ .w = flow_indent } });
    protoBadge(f.proto);

    var buf: [format.endpoint_buf_len]u8 = undefined;
    const remote = format.endpoint(&buf, f, .remote);
    const name = f.remote_hostname orelse {
        // Nothing was resolved for this address, so the endpoint is everything
        // known and it carries the line on its own.
        dvui.label(@src(), "{s}", .{remote}, .{ .gravity_y = 0.5, .color_text = pen.text });
        return;
    };
    // A Hint is a name nobody was observed resolving (CONTEXT.md), so it
    // renders dimmed and never passes for the name the process asked for.
    dvui.label(@src(), "{s}", .{name}, .{
        .gravity_y = 0.5,
        .color_text = if (f.hostname_origin == .observed) pen.text else style.dim,
    });
    // The endpoint stays, behind the name: the name is a label on an address,
    // and the address is the thing that was actually talked to.
    dvui.label(@src(), "{s}", .{remote}, .{
        .gravity_y = 0.5,
        .color_text = style.dim,
        .font = style.caption(),
    });
}

/// The colour-and-initial badge standing in for a real exe icon in v1
/// (issue #10). Every row gets one, so the names line up in a column.
fn processBadge(r: snapshot.Row) void {
    const letter = [1]u8{format.initial(r.name)};
    dvui.label(@src(), "{s}", .{&letter}, .{
        .background = true,
        .color_fill = style.processBadge(r.name),
        .color_text = .{ .r = 0xff, .g = 0xff, .b = 0xff },
        .corners = .all(100),
        .min_size_content = .{ .w = 13, .h = 13 },
        .padding = .{ .x = 4, .y = 1, .w = 4, .h = 1 },
        .margin = .{ .x = 2, .y = 2, .w = 4, .h = 2 },
        .gravity_y = 0.5,
        .font = style.captionHeading(),
    });
}

/// The protocol tag at the head of a Flow's line.
fn protoBadge(proto: engine.event.Proto) void {
    dvui.label(@src(), "{s}", .{view.info.protocol(proto)}, .{
        .background = true,
        .color_fill = style.protoFill(proto),
        .color_text = style.badge_text,
        .corners = .all(3),
        .padding = .{ .x = 3, .y = 0, .w = 3, .h = 0 },
        .margin = .{ .x = 2, .y = 2, .w = 4, .h = 2 },
        .gravity_y = 0.5,
        .font = style.caption(),
    });
}

/// Numbers right-align, so their magnitudes line up down the column.
fn numberOpts(color: ?dvui.Color) dvui.Options {
    return .{ .expand = .horizontal, .gravity_x = 1.0, .color_text = color };
}

/// Active flow count · global down/up · session totals — and, when it applies,
/// the one caveat the totals carry.
fn statusBar(snap: *const snapshot.Snapshot) void {
    const t = view.totals.of(snap);

    var bar = dvui.box(@src(), .{ .dir = .horizontal }, .{
        .expand = .horizontal,
        .background = true,
        .style = .control,
        .padding = .{ .x = 8, .y = 3, .w = 8, .h = 3 },
    });
    defer bar.deinit();

    var down: [format.rate_buf_len]u8 = undefined;
    var up: [format.rate_buf_len]u8 = undefined;
    var recv: [format.bytes_buf_len]u8 = undefined;
    var sent: [format.bytes_buf_len]u8 = undefined;

    dvui.label(@src(), "{d} active flows", .{t.active_flows}, statusOpts(style.dim));
    dvui.label(@src(), "·  down {s}  up {s}", .{
        format.rate(&down, t.down_rate),
        format.rate(&up, t.up_rate),
    }, statusOpts(style.dim));
    dvui.label(@src(), "·  session {s} down / {s} up", .{
        format.bytes(&recv, t.session_recv),
        format.bytes(&sent, t.session_sent),
    }, statusOpts(style.dim));

    // Sticky for the session once any loss occurred: the totals are honest or
    // marked, never silently low (spec issue #18).
    if (snap.health.rebaselined) {
        var opts = statusOpts(style.warn);
        opts.gravity_x = 1.0;
        dvui.label(@src(), "re-baselined — totals may undercount", .{}, opts);
    }
}

fn statusOpts(color: dvui.Color) dvui.Options {
    return .{ .color_text = color, .gravity_y = 0.5 };
}
