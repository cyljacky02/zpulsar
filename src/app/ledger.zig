//! The Ledger: one dense sortable table of Process Rows, and a status bar
//! under it. This is the layout the UI prototype settled on (variant A), minus
//! the Info View, which is not part of this ticket.
//!
//! The frame reads a Snapshot it does not own and allocates nothing per cell —
//! every number is formatted into a stack buffer. What it *does* own is the
//! row order, and that survives across frames, across Snapshots, and across
//! the teardown-recreate cycle: the ordering lives here, not in the dvui
//! context that gets destroyed when the window closes.

const std = @import("std");
const dvui = @import("dvui");
const engine = @import("engine");
const view = @import("view.zig");

const snapshot = engine.snapshot;
const format = view.format;
const order = view.order;

/// Secondary text: PIDs, session totals, the status bar, and whole rows that
/// have exited.
const dim: dvui.Color = .{ .r = 0x8a, .g = 0x8f, .b = 0x98 };
/// Reserved for the one thing the status bar can say that is bad news.
const warn: dvui.Color = .{ .r = 0xd8, .g = 0x60, .b = 0x60 };

/// The table, declared once (spec issue #24: Process, PID, Down, Up, Down
/// total, Up total). Position in this list *is* the column index, so the
/// header row, the cells, and the sort round-trip cannot drift apart.
const columns = [_]Column{
    .{ .field = .name, .label = "Process", .min_width = 260 },
    .{ .field = .pid, .label = "PID", .min_width = 60 },
    .{ .field = .down, .label = "Down", .min_width = 88 },
    .{ .field = .up, .label = "Up", .min_width = 88 },
    .{ .field = .down_total, .label = "Down total", .min_width = 92 },
    .{ .field = .up_total, .label = "Up total", .min_width = 92 },
};

const Column = struct {
    field: order.Field,
    label: []const u8,
    min_width: f32,

    /// Which way a column sorts when it is reached for the first time: the way
    /// that column is worth reaching for. Busiest first for anything numeric,
    /// A–Z for a name.
    fn firstClick(self: Column) order.Direction {
        return switch (self.field) {
            .name, .pid => .ascending,
            .down, .up, .down_total, .up_total => .descending,
        };
    }
};

fn columnOf(field: order.Field) usize {
    for (columns, 0..) |c, i| {
        if (c.field == field) return i;
    }
    unreachable; // every Field has a column, by the table above
}

const col_process = columnOf(.name);
const col_pid = columnOf(.pid);
const col_down = columnOf(.down);
const col_up = columnOf(.up);
const col_down_total = columnOf(.down_total);
const col_up_total = columnOf(.up_total);

pub const Ledger = struct {
    ordering: order.Ordering = .{},

    pub fn deinit(self: *Ledger, gpa: std.mem.Allocator) void {
        self.ordering.deinit(gpa);
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

        self.table(gpa, snap, now_ms);
        statusBar(snap);
    }

    fn table(
        self: *Ledger,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        now_ms: u64,
    ) void {
        const display = self.ordering.display(gpa, snap.rows, now_ms);

        var grid: dvui.GridWidget = undefined;
        grid.init(@src(), .{ .rows = display.len }, .{
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
        // processes and the window shows tens of them.
        const first, const last = grid.rowsVisible();
        for (first..last) |row| {
            if (row >= display.len) break;
            cells(&grid, row, snap.rows[display[row]]);
        }
    }

    fn header(self: *Ledger, grid: *dvui.GridWidget, col: usize, column: Column) void {
        const cell = grid.colHeader(col, .{});
        defer cell.deinit();
        const clicked = cell.headerSortable(column.label, .{
            .min_size_content = .{ .w = column.min_width },
        }) orelse return;
        // Clicking the column you are already on flips it, which is what the
        // widget reports; reaching a new one starts it where that column is
        // worth starting.
        const direction: order.Direction = if (self.ordering.field != column.field)
            column.firstClick()
        else switch (clicked) {
            .ascending => .ascending,
            .descending, .unsorted => .descending,
        };
        self.ordering.sortBy(column.field, direction);
    }
};

fn cells(grid: *dvui.GridWidget, row: usize, r: snapshot.Row) void {
    // Exited rows stay all session with their totals intact, dimmed
    // (CONTEXT.md "Process Row"). Dimming the whole row is what separates
    // "this process is quiet" from "this process is gone".
    const text_color: ?dvui.Color = if (r.exited) dim else null;

    processCell(grid, row, r, text_color);
    {
        var cell = grid.cell(.{ .col = col_pid, .row = row }, .{});
        defer cell.deinit();
        // The Evicted-processes Row owns no PID — it is where attribution
        // stops (CONTEXT.md), and a number there would be a lie.
        if (r.evicted_processes)
            dvui.label(@src(), "{s}", .{format.idle}, numberOpts(dim))
        else
            dvui.label(@src(), "{d}", .{r.pid}, numberOpts(text_color orelse dim));
    }

    var buf: [format.rate_buf_len]u8 = undefined;
    numberCell(grid, col_down, row, r.recv_rate, format.rate(&buf, r.recv_rate), text_color);
    numberCell(grid, col_up, row, r.sent_rate, format.rate(&buf, r.sent_rate), text_color);
    numberCell(grid, col_down_total, row, r.recv, format.bytes(&buf, r.recv), text_color);
    numberCell(grid, col_up_total, row, r.sent, format.bytes(&buf, r.sent), text_color);
}

fn processCell(grid: *dvui.GridWidget, row: usize, r: snapshot.Row, text_color: ?dvui.Color) void {
    var cell = grid.cell(.{ .col = col_process, .row = row }, .{});
    defer cell.deinit();
    var hbox = dvui.box(@src(), .{ .dir = .horizontal }, .{ .expand = .horizontal });
    defer hbox.deinit();

    dvui.label(@src(), "{s}", .{format.processName(r.name)}, .{
        .gravity_y = 0.5,
        .color_text = text_color,
    });
    // Service Attribution (CONTEXT.md): one service means the row *is* that
    // service; several mean a shared host, and the honest fallback names the
    // count rather than picking one.
    if (r.services.len == 1) {
        dvui.label(@src(), "· {s}", .{r.services[0]}, .{ .gravity_y = 0.5, .color_text = dim });
    } else if (r.services.len > 1) {
        dvui.label(@src(), "· {d} services", .{r.services.len}, .{ .gravity_y = 0.5, .color_text = dim });
    }
    if (r.exited and !r.evicted_processes)
        dvui.label(@src(), "(exited)", .{}, .{ .gravity_y = 0.5, .color_text = dim });
}

fn numberCell(
    grid: *dvui.GridWidget,
    col: usize,
    row: usize,
    value: u64,
    text: []const u8,
    text_color: ?dvui.Color,
) void {
    var cell = grid.cell(.{ .col = col, .row = row }, .{});
    defer cell.deinit();
    // A cell with nothing in it is already a dash; dimming it too keeps the
    // eye on the rows that are actually moving.
    dvui.label(@src(), "{s}", .{text}, numberOpts(if (value == 0) dim else text_color));
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

    dvui.label(@src(), "{d} active flows", .{t.active_flows}, statusOpts(dim));
    dvui.label(@src(), "·  down {s}  up {s}", .{
        format.rate(&down, t.down_rate),
        format.rate(&up, t.up_rate),
    }, statusOpts(dim));
    dvui.label(@src(), "·  session {s} down / {s} up", .{
        format.bytes(&recv, t.session_recv),
        format.bytes(&sent, t.session_sent),
    }, statusOpts(dim));

    // Sticky for the session once any loss occurred: the totals are honest or
    // marked, never silently low (spec issue #18).
    if (snap.health.rebaselined) {
        var opts = statusOpts(warn);
        opts.gravity_x = 1.0;
        dvui.label(@src(), "re-baselined — totals may undercount", .{}, opts);
    }
}

fn statusOpts(color: dvui.Color) dvui.Options {
    return .{ .color_text = color, .gravity_y = 0.5 };
}
