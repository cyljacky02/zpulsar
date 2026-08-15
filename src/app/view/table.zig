//! What the Ledger has on screen: the lines, which Process Rows are expanded,
//! and what the Info View is looking at.
//!
//! A line is a Process Row, or one of its Flows shown inline beneath it
//! (locked layout, issue #10). Expansion and selection are the user's, so they
//! outlive the Snapshot they were made against — and the teardown-recreate
//! cycle that destroys every widget — which means neither can be stored as an
//! index. Both are held as keys and re-resolved against each Snapshot, once
//! per frame.

const std = @import("std");
const engine = @import("engine");
const order = @import("order.zig");

const snapshot = engine.snapshot;

/// One line of the table: a Process Row, or one Flow shown beneath it.
/// Addressed by index into the Snapshot `build` was given, so a Line never
/// outlives it.
pub const Line = struct {
    /// Index into `Snapshot.rows`.
    row: u32,
    /// Index into that Row's own `flows`; null on the Process Row's own line.
    flow: ?u32 = null,
};

/// One Flow, across Snapshots: the identity the Engine sorts its Flows by
/// (core.zig `entryLessThan`) plus the Generation, so a selection cannot
/// silently follow a reused endpoint pair into a different conversation
/// (CONTEXT.md "Generation").
pub const FlowKey = struct {
    proto: engine.event.Proto,
    family: engine.event.Family,
    local_addr: [16]u8,
    remote_addr: [16]u8,
    local_port: u16,
    remote_port: u16,
    group_kind: engine.event.GroupKind,
    generation: u32,
};

/// What the Info View is looking at, as indices into the Snapshot the last
/// `build` was given.
pub const Inspected = union(enum) {
    nothing,
    process: u32,
    flow: struct { row: u32, flow: u32 },
};

/// What the user picked, in terms that outlive a Snapshot.
const Selection = struct {
    row: order.Key,
    /// Null when a Process Row itself is selected.
    flow: ?FlowKey = null,
};

pub const Table = struct {
    /// The Process Rows the user has opened, by row key. A set rather than a
    /// flag on the row: the rows are the Engine's and are rebuilt every
    /// Snapshot.
    expanded: std.AutoHashMapUnmanaged(order.Key, void) = .empty,
    /// Reused across frames: the lines, rebuilt each one.
    lines: std.ArrayList(Line) = .empty,
    /// The selection as keys — what survives a Snapshot.
    selection: ?Selection = null,
    /// The same selection as indices into the current Snapshot — what the
    /// frame draws with. Re-resolved by every `build`.
    current: Inspected = .nothing,

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        self.expanded.deinit(gpa);
        self.lines.deinit(gpa);
    }

    /// The lines to draw, in display order: every Process Row in `display`,
    /// each expanded one followed by its Flows. Valid until the next call, and
    /// only against `snap`.
    pub fn build(
        self: *Table,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        display: []const u32,
    ) []const Line {
        self.resolveSelection(snap);
        self.lines.clearRetainingCapacity();
        for (display) |row_idx| {
            const row = snap.rows[row_idx];
            // Under memory pressure the table shows the lines it has room for:
            // a short table is a degraded view, a crash is no view at all —
            // the same bargain order.zig strikes.
            self.lines.append(gpa, .{ .row = row_idx }) catch break;
            if (!self.adoptExpansion(gpa, row)) continue;
            for (0..row.flows.len) |flow_idx|
                self.lines.append(gpa, .{ .row = row_idx, .flow = @intCast(flow_idx) }) catch break;
        }
        return self.lines.items;
    }

    /// Whether this Process Row's Flows are showing — what the chevron draws
    /// from. Exact, because `build` has already moved any open state onto the
    /// row's current key.
    pub fn isExpanded(self: *const Table, row: snapshot.Row) bool {
        return self.expanded.contains(keyOf(row));
    }

    /// `isExpanded`, plus the one case where the key moved underneath the
    /// user: a placeholder row that has since been adopted in place keeps the
    /// state it was opened with, re-filed under the key it now has so nothing
    /// stale is left behind to catch a reused PID later.
    fn adoptExpansion(self: *Table, gpa: std.mem.Allocator, row: snapshot.Row) bool {
        if (self.isExpanded(row)) return true;
        if (row.create_time == 0) return false;
        if (!self.expanded.remove(.{ .pid = row.pid, .create_time = 0 })) return false;
        self.expanded.put(gpa, keyOf(row), {}) catch {};
        return true;
    }

    /// Open or close a Process Row. On memory pressure the row stays as it
    /// was: a click that does nothing is better than one that half-works.
    pub fn toggle(self: *Table, gpa: std.mem.Allocator, row: snapshot.Row) void {
        const key = keyOf(row);
        if (self.expanded.remove(key)) return;
        self.expanded.put(gpa, key, {}) catch {};
    }

    /// A click landed on `line` — the click model the layout lock fixed
    /// (issue #10): a Process Row click selects it *and* toggles its Flows; a
    /// Flow click selects that Flow for inspection and touches nothing else.
    /// `line` must be one this `build` returned for `snap`.
    pub fn click(
        self: *Table,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        line: Line,
    ) void {
        const row = snap.rows[line.row];
        if (line.flow) |flow_idx| {
            self.selection = .{ .row = keyOf(row), .flow = flowKeyOf(row.flows[flow_idx]) };
            self.current = .{ .flow = .{ .row = line.row, .flow = flow_idx } };
            return;
        }
        self.selection = .{ .row = keyOf(row) };
        self.current = .{ .process = line.row };
        self.toggle(gpa, row);
    }

    /// What the Info View shows, against the Snapshot of the last `build`.
    pub fn inspected(self: *const Table) Inspected {
        return self.current;
    }

    /// Whether this line is the selected one — the blue accent in the locked
    /// layout.
    pub fn isSelected(self: *const Table, line: Line) bool {
        return switch (self.current) {
            .nothing => false,
            .process => |row| line.flow == null and line.row == row,
            .flow => |f| line.row == f.row and line.flow == f.flow,
        };
    }

    /// Point the selection at the Snapshot in hand. Rows and Flows move
    /// between Snapshots — they are rebuilt, re-sorted, and eventually gone —
    /// so the keys are what the user picked and these indices are only ever
    /// this frame's answer.
    fn resolveSelection(self: *Table, snap: *const snapshot.Snapshot) void {
        self.current = .nothing;
        const sel = self.selection orelse return;
        const row_idx = findRow(snap.rows, sel.row) orelse {
            // The row is gone for good — evicted, or never published again.
            self.selection = null;
            return;
        };
        // Re-key: a placeholder row whose identity has since arrived is the
        // same Process Row, adopted in place (core.zig), and the selection
        // follows it rather than being dropped on the frame it gets its name.
        self.selection.?.row = keyOf(snap.rows[row_idx]);
        if (sel.flow) |flow_key| {
            if (findFlow(snap.rows[row_idx].flows, flow_key)) |flow_idx| {
                self.current = .{ .flow = .{ .row = row_idx, .flow = flow_idx } };
                return;
            }
            // The Flow is gone: it closed, Lingered, and was removed. Its
            // process is the nearest thing still true, and an Info View that
            // emptied itself mid-inspection would read as a bug.
            self.selection.?.flow = null;
        }
        self.current = .{ .process = row_idx };
    }
};

fn findRow(rows: []const snapshot.Row, key: order.Key) ?u32 {
    for (rows, 0..) |row, i| {
        if (row.pid == key.pid and row.create_time == key.create_time) return @intCast(i);
    }
    // A key half-known when it was taken names the live instance of that PID:
    // the placeholder it came from has since been adopted (see above).
    if (key.create_time == 0) {
        for (rows, 0..) |row, i| {
            if (row.pid == key.pid and !row.exited) return @intCast(i);
        }
    }
    return null;
}

fn findFlow(flows: []const snapshot.Flow, key: FlowKey) ?u32 {
    for (flows, 0..) |f, i| {
        if (std.meta.eql(flowKeyOf(f), key)) return @intCast(i);
    }
    return null;
}

fn flowKeyOf(f: snapshot.Flow) FlowKey {
    return .{
        .proto = f.proto,
        .family = f.family,
        .local_addr = f.local_addr,
        .remote_addr = f.remote_addr,
        .local_port = f.local_port,
        .remote_port = f.remote_port,
        .group_kind = f.group_kind,
        .generation = f.generation,
    };
}

fn keyOf(row: snapshot.Row) order.Key {
    return .{ .pid = row.pid, .create_time = row.create_time };
}

const testing = std.testing;

/// A Snapshot built the way the Engine publishes one: each row's `flows` is a
/// sub-slice of the flat flow array, in the order it hangs them
/// (core.zig `entryLessThan`).
fn testSnapshot(
    rows: []const snapshot.Row,
    per_row: []const []const snapshot.Flow,
) !*snapshot.Snapshot {
    var total: usize = 0;
    for (per_row) |fs| total += fs.len;

    const snap = try snapshot.create(testing.allocator, rows.len, total);
    const flat = snapshot.mutableFlows(snap);
    var at: usize = 0;
    for (snapshot.mutableRows(snap), rows, 0..) |*dst, src, i| {
        dst.* = src;
        dst.name = try snapshot.arenaDupe(snap, src.name);
        const fs = if (i < per_row.len) per_row[i] else &.{};
        @memcpy(flat[at..][0..fs.len], fs);
        dst.flows = flat[at..][0..fs.len];
        at += fs.len;
    }
    return snap;
}

/// A TCP Flow, told apart from its neighbours by its local port.
fn testFlow(local_port: u16) snapshot.Flow {
    return .{
        .proto = .tcp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = local_port,
        .remote_port = 443,
        .generation = 1,
    };
}

/// The display order the Ledger's frozen Ordering would hand in — here, the
/// rows as the Snapshot has them.
fn identityOrder(gpa: std.mem.Allocator, count: usize) ![]const u32 {
    const out = try gpa.alloc(u32, count);
    for (out, 0..) |*dst, i| dst.* = @intCast(i);
    return out;
}

test "a Process Row stands alone until it is expanded, then its Flows follow it" {
    const snap = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" },
        .{ .pid = 2, .create_time = 2, .name = "C:\\b.exe" },
    }, &.{
        &.{ testFlow(1000), testFlow(1001) },
        &.{testFlow(2000)},
    });
    defer snap.release();
    const display = try identityOrder(testing.allocator, snap.rows.len);
    defer testing.allocator.free(display);

    var table: Table = .{};
    defer table.deinit(testing.allocator);

    // Collapsed: one line each, and no sign of the Flows underneath.
    try testing.expectEqualSlices(Line, &.{
        .{ .row = 0 },
        .{ .row = 1 },
    }, table.build(testing.allocator, snap, display));

    // Expanding one row inserts its Flows directly beneath it — and leaves
    // every other row where it was.
    table.toggle(testing.allocator, snap.rows[0]);
    try testing.expectEqualSlices(Line, &.{
        .{ .row = 0 },
        .{ .row = 0, .flow = 0 },
        .{ .row = 0, .flow = 1 },
        .{ .row = 1 },
    }, table.build(testing.allocator, snap, display));

    // And collapsing takes them away again.
    table.toggle(testing.allocator, snap.rows[0]);
    try testing.expectEqualSlices(Line, &.{
        .{ .row = 0 },
        .{ .row = 1 },
    }, table.build(testing.allocator, snap, display));
}

/// The two-row, three-Flow Snapshot the click-model tests share.
fn clickFixture() !*snapshot.Snapshot {
    return testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" },
        .{ .pid = 2, .create_time = 2, .name = "C:\\b.exe" },
    }, &.{
        &.{ testFlow(1000), testFlow(1001) },
        &.{testFlow(2000)},
    });
}

test "a click on a Process Row selects it and toggles its Flows" {
    const snap = try clickFixture();
    defer snap.release();
    const display = try identityOrder(testing.allocator, snap.rows.len);
    defer testing.allocator.free(display);

    var table: Table = .{};
    defer table.deinit(testing.allocator);
    _ = table.build(testing.allocator, snap, display);
    // Nothing is selected until something is clicked — the Info View has an
    // empty state to show for exactly this.
    try testing.expectEqual(Inspected.nothing, table.inspected());

    table.click(testing.allocator, snap, .{ .row = 0 });
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
    // The one click did both: selected the row *and* opened it.
    try testing.expectEqual(@as(usize, 4), table.build(testing.allocator, snap, display).len);
    try testing.expect(table.isSelected(.{ .row = 0 }));
    try testing.expect(!table.isSelected(.{ .row = 0, .flow = 0 }));
    try testing.expect(!table.isSelected(.{ .row = 1 }));

    // Clicking it again closes it, and it is still the row being inspected —
    // collapsing is not deselecting.
    table.click(testing.allocator, snap, .{ .row = 0 });
    try testing.expectEqual(@as(usize, 2), table.build(testing.allocator, snap, display).len);
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
}

test "a click on a Flow inspects it, and leaves the expansion where it was" {
    const snap = try clickFixture();
    defer snap.release();
    const display = try identityOrder(testing.allocator, snap.rows.len);
    defer testing.allocator.free(display);

    var table: Table = .{};
    defer table.deinit(testing.allocator);
    table.click(testing.allocator, snap, .{ .row = 0 });
    _ = table.build(testing.allocator, snap, display);

    table.click(testing.allocator, snap, .{ .row = 0, .flow = 1 });
    try testing.expectEqual(Inspected{ .flow = .{ .row = 0, .flow = 1 } }, table.inspected());
    // Still open: a Flow click would otherwise close the very list it was
    // clicked in, and the row would jump out from under the cursor.
    try testing.expectEqual(@as(usize, 4), table.build(testing.allocator, snap, display).len);
    try testing.expect(table.isSelected(.{ .row = 0, .flow = 1 }));
    try testing.expect(!table.isSelected(.{ .row = 0, .flow = 0 }));
    try testing.expect(!table.isSelected(.{ .row = 0 }));
}

test "the selection follows its Flow when the next Snapshot moves it" {
    const before = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{ testFlow(1000), testFlow(1001), testFlow(1002) }},
    );
    defer before.release();
    const display = try identityOrder(testing.allocator, 1);
    defer testing.allocator.free(display);

    var table: Table = .{};
    defer table.deinit(testing.allocator);
    table.click(testing.allocator, before, .{ .row = 0 });
    _ = table.build(testing.allocator, before, display);
    table.click(testing.allocator, before, .{ .row = 0, .flow = 2 });

    // The first Flow closed and was removed, so every later one shifts up by
    // one index. Following the index would now inspect the wrong conversation.
    const after = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{ testFlow(1001), testFlow(1002) }},
    );
    defer after.release();
    _ = table.build(testing.allocator, after, display);
    try testing.expectEqual(Inspected{ .flow = .{ .row = 0, .flow = 1 } }, table.inspected());
}

test "a Flow that ends leaves its own process selected" {
    const before = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{ testFlow(1000), testFlow(1001) }},
    );
    defer before.release();
    const display = try identityOrder(testing.allocator, 1);
    defer testing.allocator.free(display);

    var table: Table = .{};
    defer table.deinit(testing.allocator);
    table.click(testing.allocator, before, .{ .row = 0, .flow = 1 });

    // Closed, Lingered, and finally dropped: the Info View falls back to the
    // process rather than emptying itself out from under the reader.
    const after = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{testFlow(1000)}},
    );
    defer after.release();
    _ = table.build(testing.allocator, after, display);
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
}

test "a row the Eviction cap took stops being inspected" {
    const before = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" },
        .{ .pid = 2, .create_time = 2, .name = "C:\\gone.exe" },
    }, &.{});
    defer before.release();
    const two = try identityOrder(testing.allocator, 2);
    defer testing.allocator.free(two);

    var table: Table = .{};
    defer table.deinit(testing.allocator);
    table.click(testing.allocator, before, .{ .row = 1 });

    const after = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" },
    }, &.{});
    defer after.release();
    const one = try identityOrder(testing.allocator, 1);
    defer testing.allocator.free(one);
    _ = table.build(testing.allocator, after, one);
    // Nothing left to inspect, and above all not whichever row inherited
    // index 1.
    try testing.expectEqual(Inspected.nothing, table.inspected());
}

test "an open, inspected row stays open and inspected when its identity arrives" {
    // A placeholder: traffic reached the Engine before the process rundown
    // named it, so half its row key is still zero (snapshot.Row).
    const before = try testSnapshot(
        &.{.{ .pid = 7, .create_time = 0, .name = "" }},
        &.{&.{testFlow(1000)}},
    );
    defer before.release();
    const display = try identityOrder(testing.allocator, 1);
    defer testing.allocator.free(display);

    var table: Table = .{};
    defer table.deinit(testing.allocator);
    table.click(testing.allocator, before, .{ .row = 0 });
    try testing.expectEqual(@as(usize, 2), table.build(testing.allocator, before, display).len);

    // The Engine adopts the placeholder in place — same row, same totals, new
    // key. A row that closed and deselected itself the moment it learned its
    // own name would be a reorder nobody asked for.
    const after = try testSnapshot(
        &.{.{ .pid = 7, .create_time = 777, .name = "C:\\b.exe" }},
        &.{&.{testFlow(1000)}},
    );
    defer after.release();
    try testing.expectEqual(@as(usize, 2), table.build(testing.allocator, after, display).len);
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
}
