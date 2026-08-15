//! The Info View: the right-docked panel the Ledger's selection drives
//! (locked layout, issue #10). It is always visible in v1 — a panel that
//! appears and disappears would reflow the table under the cursor — and it
//! ends in a Tools section of reserved, inert entries, so the per-address
//! tools of v2 land in space the layout already guarantees.
//!
//! What each section *says* is decided in `view/info.zig`, where it is
//! testable without a device; this file places it. The only state it owns is
//! which sections are open, and it owns that rather than letting dvui remember
//! it: dvui's memory dies with the context, and closing the window must not
//! quietly reopen every section.

const std = @import("std");
const dvui = @import("dvui");
const engine = @import("engine");

const style = @import("style.zig");
const view = @import("view.zig");

const snapshot = engine.snapshot;
const format = view.format;
const info = view.info;

/// The dock's width, from the layout lock: wide enough for a v6 endpoint and a
/// hostname at caption size, narrow enough to leave the table the window.
const width = 300;

pub const InfoView = struct {
    /// Which sections are open. The panel has three of them — properties,
    /// activity, tools — and what changes with the selection is their
    /// *contents*, not which sections exist; so a section a reader collapsed
    /// stays collapsed as they click from a process to a flow, rather than
    /// springing back open under them. Defaults match the locked screenshots:
    /// all open, because a panel that opens empty teaches nothing.
    properties_open: bool = true,
    activity_open: bool = true,
    tools_open: bool = true,

    /// One frame. `inspected` must have come from the same Snapshot — it
    /// indexes into it.
    pub fn frame(
        self: *InfoView,
        snap: *const snapshot.Snapshot,
        inspected: view.table.Inspected,
    ) void {
        var panel = dvui.box(@src(), .{ .dir = .vertical }, .{
            .expand = .vertical,
            .min_size_content = .{ .w = width },
            .max_size_content = .width(width),
            .background = true,
            .style = .window,
            .padding = .{ .x = 10, .y = 6, .w = 10, .h = 6 },
        });
        defer panel.deinit();

        dvui.label(@src(), "INFO VIEW", .{}, .{
            .color_text = style.dim,
            .font = style.captionHeading(),
        });

        var scroll = dvui.scrollArea(@src(), .{}, .{ .expand = .both });
        defer scroll.deinit();

        switch (inspected) {
            .nothing => dvui.label(@src(), "Select a process or flow", .{}, .{
                .color_text = style.dim,
                .gravity_x = 0.5,
                .padding = .{ .x = 0, .y = 30, .w = 0, .h = 0 },
            }),
            .process => |row| self.process(snap.rows[row]),
            .flow => |sel| {
                const row = snap.rows[sel.row];
                self.flow(row, row.flows[sel.flow]);
            },
        }
    }

    fn process(self: *InfoView, r: snapshot.Row) void {
        dvui.label(@src(), "Process", .{}, .{ .color_text = style.accent, .font = style.title() });
        dvui.label(@src(), "{s}", .{format.processName(r.name)}, .{ .font = style.captionHeading() });
        // Service Attribution, said once at the top the way the row says it.
        if (r.services.len == 1)
            dvui.label(@src(), "{s}", .{r.services[0]}, .{ .color_text = style.dim, .font = style.caption() })
        else if (r.services.len > 1)
            dvui.label(@src(), "{d} services", .{r.services.len}, .{ .color_text = style.dim, .font = style.caption() });

        var fields: info.Fields = .{};
        info.processProperties(&fields, r);
        if (dvui.expander(@src(), "Process properties", .{ .expanded = &self.properties_open }, sectionOpts()))
            fieldList(@src(), &fields);

        var activity: info.Fields = .{};
        info.processActivity(&activity, r);
        if (dvui.expander(@src(), "Activity", .{ .expanded = &self.activity_open }, sectionOpts()))
            fieldList(@src(), &activity);

        if (dvui.expander(@src(), "Tools", .{ .expanded = &self.tools_open }, sectionOpts()))
            tools(@src(), &info.process_tools);
    }

    fn flow(self: *InfoView, r: snapshot.Row, f: snapshot.Flow) void {
        dvui.label(@src(), "Flow", .{}, .{ .color_text = style.accent, .font = style.title() });
        // Titled by the name if there is one, and by the endpoint if not —
        // whichever is the thing the reader actually clicked on.
        var buf: [format.endpoint_buf_len]u8 = undefined;
        if (f.remote_hostname) |name| {
            dvui.label(@src(), "{s}", .{name}, .{
                .font = style.captionHeading(),
                .color_text = if (f.hostname_origin == .observed) null else style.dim,
            });
        } else {
            dvui.label(@src(), "{s}", .{format.endpoint(&buf, f, .remote)}, .{
                .font = style.captionHeading(),
            });
        }
        // Whose conversation this is: the process, and the service inside it
        // when a shared host means the row's own name is not the answer.
        if (f.service) |svc|
            dvui.label(@src(), "{s} · {s}", .{ format.processName(r.name), svc }, subtitleOpts())
        else
            dvui.label(@src(), "{s}", .{format.processName(r.name)}, subtitleOpts());
        if (f.lingering)
            dvui.label(@src(), "closed — still shown", .{}, subtitleOpts());

        var fields: info.Fields = .{};
        info.flowProperties(&fields, f);
        if (dvui.expander(@src(), "Flow properties", .{ .expanded = &self.properties_open }, sectionOpts()))
            fieldList(@src(), &fields);

        var activity: info.Fields = .{};
        info.flowActivity(&activity, f);
        if (dvui.expander(@src(), "Activity", .{ .expanded = &self.activity_open }, sectionOpts()))
            fieldList(@src(), &activity);

        if (dvui.expander(@src(), "Tools", .{ .expanded = &self.tools_open }, sectionOpts()))
            tools(@src(), &info.flow_tools);
    }
};

fn sectionOpts() dvui.Options {
    return .{ .expand = .horizontal, .font = style.captionHeading() };
}

fn subtitleOpts() dvui.Options {
    return .{ .color_text = style.dim, .font = style.caption() };
}

/// One section's fields. `src` comes from the call site: every section is a
/// separate widget tree, and sharing one source location would have them share
/// one identity.
fn fieldList(src: std.builtin.SourceLocation, fields: *const info.Fields) void {
    var box = dvui.box(src, .{ .dir = .vertical }, .{
        .expand = .horizontal,
        .margin = .{ .x = 12, .y = 2, .w = 0, .h = 6 },
    });
    defer box.deinit();

    for (fields.slice(), 0..) |f, i| {
        var row = dvui.box(@src(), .{ .dir = .horizontal }, .{
            .id_extra = i,
            .expand = .horizontal,
        });
        defer row.deinit();
        dvui.label(@src(), "{s}", .{f.label}, .{
            .color_text = style.dim,
            .font = style.caption(),
            .min_size_content = .{ .w = 88 },
            .gravity_y = 0.5,
        });
        dvui.label(@src(), "{s}", .{fields.value(f)}, .{
            .font = style.caption(),
            .gravity_y = 0.5,
            .color_text = if (f.dim) style.dim else null,
        });
    }
}

/// The Tools section: names only. They are reserved extension points, not
/// implemented in v1 (issue #10), so they are rendered inert and labelled as
/// such rather than offered as buttons that do nothing.
fn tools(src: std.builtin.SourceLocation, names: []const []const u8) void {
    var box = dvui.box(src, .{ .dir = .vertical }, .{
        .expand = .horizontal,
        .margin = .{ .x = 12, .y = 2, .w = 0, .h = 6 },
    });
    defer box.deinit();

    for (names, 0..) |name, i| {
        dvui.label(@src(), "{s}", .{name}, .{
            .id_extra = i,
            .color_text = style.accent,
            .font = style.caption(),
            .padding = .{ .x = 0, .y = 1, .w = 0, .h = 1 },
        });
    }
    dvui.label(@src(), "{s}", .{info.tools_note}, .{
        .color_text = style.dim,
        .font = style.caption(),
        .padding = .{ .x = 0, .y = 3, .w = 0, .h = 0 },
    });
}
