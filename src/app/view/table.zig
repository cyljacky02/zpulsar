//! What the Ledger has on screen: the lines, which of them are open, and what
//! the Info View is looking at.
//!
//! Three levels (issue #47): a Program, the Process Rows that are instances of
//! it, and a row's Flows shown inline beneath it. Expansion and selection are
//! the user's, so they outlive the Snapshot they were made against — and the
//! teardown-recreate cycle that destroys every widget — which means neither
//! can be stored as an index. Both are held as keys and re-resolved against
//! each Snapshot, once per frame.

const std = @import("std");
const engine = @import("engine");
const order = @import("order.zig");
const programs = @import("programs.zig");

const snapshot = engine.snapshot;

/// One line of the table, addressed by index into the Snapshot and Program
/// list `build` was given, so a Line never outlives them.
///
/// The three levels are the three shapes this takes: a Program alone, a
/// Program and one of its instances, or both and one of that instance's Flows.
pub const Line = struct {
    /// Index into the Program list.
    program: u32,
    /// Index into `Snapshot.rows`; null on the Program's own line.
    row: ?u32 = null,
    /// Index into that row's own `flows`; null unless this is a Flow line.
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

/// What the Info View is looking at, as indices into the Snapshot and Program
/// list the last `build` was given.
pub const Inspected = union(enum) {
    nothing,
    program: u32,
    process: u32,
    flow: struct { row: u32, flow: u32 },
};

/// What the user picked, in terms that outlive a Snapshot — one variant per
/// level, so a selection cannot describe half of one thing and half of
/// another.
const Selection = union(enum) {
    /// A Program's identity hash (programs.zig).
    program: u64,
    process: order.Key,
    flow: struct { row: order.Key, flow: FlowKey },
};

pub const Table = struct {
    /// The Programs the user has opened, by identity hash.
    expanded_programs: std.AutoHashMapUnmanaged(u64, void) = .empty,
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
        self.expanded_programs.deinit(gpa);
        self.expanded.deinit(gpa);
        self.lines.deinit(gpa);
    }

    /// The lines to draw, in display order: every Program in `display`, each
    /// open one followed by its instances, and each open instance followed by
    /// its Flows. Valid until the next call, and only against `snap` and the
    /// `list` it was grouped into.
    pub fn build(
        self: *Table,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        list: []const programs.Program,
        display: []const u32,
    ) []const Line {
        self.resolveSelection(snap, list);
        self.lines.clearRetainingCapacity();
        for (display) |at| {
            const program = list[at];
            // Under memory pressure the table shows the lines it has room for:
            // a short table is a degraded view, a crash is no view at all —
            // the same bargain order.zig strikes.
            self.lines.append(gpa, .{ .program = at }) catch break;
            if (!self.isProgramExpanded(program)) continue;

            for (program.members) |row_idx| {
                const row = snap.rows[row_idx];
                self.lines.append(gpa, .{ .program = at, .row = row_idx }) catch break;
                if (!self.adoptExpansion(gpa, row)) continue;
                for (0..row.flows.len) |flow_idx| {
                    self.lines.append(gpa, .{
                        .program = at,
                        .row = row_idx,
                        .flow = @intCast(flow_idx),
                    }) catch break;
                }
            }
        }
        return self.lines.items;
    }

    /// Whether this Program's instances are showing.
    pub fn isProgramExpanded(self: *const Table, program: programs.Program) bool {
        return self.expanded_programs.contains(program.key);
    }

    /// Open or close a Program. On memory pressure it stays as it was: a click
    /// that does nothing is better than one that half-works.
    pub fn toggleProgram(self: *Table, gpa: std.mem.Allocator, program: programs.Program) void {
        if (self.expanded_programs.remove(program.key)) return;
        self.expanded_programs.put(gpa, program.key, {}) catch {};
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
    /// (issue #10), now at three levels: a click on anything with children
    /// selects it *and* opens or closes it; a Flow has none, so a Flow click
    /// only selects. `line` must be one this `build` returned for `snap`.
    pub fn click(
        self: *Table,
        gpa: std.mem.Allocator,
        snap: *const snapshot.Snapshot,
        list: []const programs.Program,
        line: Line,
    ) void {
        const row_idx = line.row orelse {
            const program = list[line.program];
            self.selection = .{ .program = program.key };
            self.current = .{ .program = line.program };
            self.toggleProgram(gpa, program);
            return;
        };
        const row = snap.rows[row_idx];
        if (line.flow) |flow_idx| {
            self.selection = .{ .flow = .{
                .row = keyOf(row),
                .flow = flowKeyOf(row.flows[flow_idx]),
            } };
            self.current = .{ .flow = .{ .row = row_idx, .flow = flow_idx } };
            return;
        }
        self.selection = .{ .process = keyOf(row) };
        self.current = .{ .process = row_idx };
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
            .program => |at| line.row == null and line.program == at,
            .process => |row| line.flow == null and line.row == row,
            .flow => |f| line.row == f.row and line.flow == f.flow,
        };
    }

    /// Point the selection at the Snapshot in hand. Programs, rows and Flows
    /// all move between Snapshots — they are regrouped, re-sorted, and
    /// eventually gone — so the keys are what the user picked and these
    /// indices are only ever this frame's answer.
    fn resolveSelection(
        self: *Table,
        snap: *const snapshot.Snapshot,
        list: []const programs.Program,
    ) void {
        self.current = .nothing;
        const sel = self.selection orelse return;
        switch (sel) {
            .program => |key| {
                for (list, 0..) |p, at| {
                    if (p.key != key) continue;
                    self.current = .{ .program = @intCast(at) };
                    return;
                }
                // Every instance of it is gone, so there is no Program left.
                self.selection = null;
            },
            .process => |key| {
                const row_idx = self.findSelectedRow(snap, key) orelse return;
                self.current = .{ .process = row_idx };
            },
            .flow => |f| {
                const row_idx = self.findSelectedRow(snap, f.row) orelse return;
                if (findFlow(snap.rows[row_idx].flows, f.flow)) |flow_idx| {
                    self.current = .{ .flow = .{ .row = row_idx, .flow = flow_idx } };
                    return;
                }
                // The Flow is gone: it closed, Lingered, and was removed. Its
                // process is the nearest thing still true, and an Info View
                // that emptied itself mid-inspection would read as a bug.
                self.selection = .{ .process = keyOf(snap.rows[row_idx]) };
                self.current = .{ .process = row_idx };
            },
        }
    }

    /// The selected row in this Snapshot, re-keying it on the way through: a
    /// placeholder row whose identity has since arrived is the same Process
    /// Row, adopted in place (core.zig), so the selection follows it rather
    /// than being dropped on the frame it gets its name. A row that cannot be
    /// found is gone for good — evicted, or never published again — and takes
    /// the selection with it.
    fn findSelectedRow(
        self: *Table,
        snap: *const snapshot.Snapshot,
        key: order.Key,
    ) ?u32 {
        const row_idx = findRow(snap.rows, key) orelse {
            self.selection = null;
            return null;
        };
        self.selection = switch (self.selection.?) {
            .program => unreachable, // a Program selection never gets here
            .process => .{ .process = keyOf(snap.rows[row_idx]) },
            .flow => |f| .{ .flow = .{ .row = keyOf(snap.rows[row_idx]), .flow = f.flow } },
        };
        return row_idx;
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

/// The Ledger's three levels, wired the way a frame wires them: group, order,
/// then lay out the lines. Owned by the caller, because a Program's members
/// are slices into the grouping.
const Frame = struct {
    grouped: programs.Programs = .{},
    ordering: order.Ordering = .{},
    list: []programs.Program = &.{},

    fn deinit(self: *Frame) void {
        self.grouped.deinit(testing.allocator);
        self.ordering.deinit(testing.allocator);
    }

    /// One frame's worth of layout.
    fn lines(self: *Frame, table: *Table, snap: *const snapshot.Snapshot) []const Line {
        self.list = self.grouped.build(testing.allocator, snap.rows);
        const display = self.ordering.display(testing.allocator, self.list, snap.rows, 0);
        return table.build(testing.allocator, snap, self.list, display);
    }
};

test "a Program stands alone until it is opened, and so do its instances" {
    const snap = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 200 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\a.exe", .recv_rate = 100 },
    }, &.{
        &.{ testFlow(1000), testFlow(1001) },
        &.{},
    });
    defer snap.release();

    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    // Two instances of one executable: one line, closed.
    try testing.expectEqualSlices(Line, &.{.{ .program = 0 }}, frame.lines(&table, snap));

    // Opening the Program shows its instances — not their Flows.
    table.toggleProgram(testing.allocator, frame.list[0]);
    try testing.expectEqualSlices(Line, &.{
        .{ .program = 0 },
        .{ .program = 0, .row = 0 },
        .{ .program = 0, .row = 1 },
    }, frame.lines(&table, snap));

    // Opening an instance shows that instance's Flows, and only that one's.
    table.toggle(testing.allocator, snap.rows[0]);
    try testing.expectEqualSlices(Line, &.{
        .{ .program = 0 },
        .{ .program = 0, .row = 0 },
        .{ .program = 0, .row = 0, .flow = 0 },
        .{ .program = 0, .row = 0, .flow = 1 },
        .{ .program = 0, .row = 1 },
    }, frame.lines(&table, snap));

    // Closing the Program takes the whole subtree with it.
    table.toggleProgram(testing.allocator, frame.list[0]);
    try testing.expectEqualSlices(Line, &.{.{ .program = 0 }}, frame.lines(&table, snap));
}

/// One Program of two instances, the first with two Flows.
fn clickFixture() !*snapshot.Snapshot {
    return testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 200 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\a.exe", .recv_rate = 100 },
    }, &.{
        &.{ testFlow(1000), testFlow(1001) },
        &.{},
    });
}

test "a click on a Program selects it and toggles its instances" {
    const snap = try clickFixture();
    defer snap.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    _ = frame.lines(&table, snap);
    // Nothing is selected until something is clicked — the Info View has an
    // empty state to show for exactly this.
    try testing.expectEqual(Inspected.nothing, table.inspected());

    table.click(testing.allocator, snap, frame.list, .{ .program = 0 });
    try testing.expectEqual(Inspected{ .program = 0 }, table.inspected());
    try testing.expectEqual(@as(usize, 3), frame.lines(&table, snap).len);
    try testing.expect(table.isSelected(.{ .program = 0 }));
    try testing.expect(!table.isSelected(.{ .program = 0, .row = 0 }));

    // Clicking it again closes it, and it is still what the Info View shows —
    // collapsing is not deselecting.
    table.click(testing.allocator, snap, frame.list, .{ .program = 0 });
    try testing.expectEqual(@as(usize, 1), frame.lines(&table, snap).len);
    try testing.expectEqual(Inspected{ .program = 0 }, table.inspected());
}

test "a click on an instance selects it and toggles its Flows" {
    const snap = try clickFixture();
    defer snap.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    _ = frame.lines(&table, snap);
    table.click(testing.allocator, snap, frame.list, .{ .program = 0 });
    _ = frame.lines(&table, snap);

    table.click(testing.allocator, snap, frame.list, .{ .program = 0, .row = 0 });
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
    // Program line, both instances, and the opened instance's two Flows.
    try testing.expectEqual(@as(usize, 5), frame.lines(&table, snap).len);
    try testing.expect(table.isSelected(.{ .program = 0, .row = 0 }));
    try testing.expect(!table.isSelected(.{ .program = 0 }));
}

test "a click on a Flow inspects it, and leaves both levels where they were" {
    const snap = try clickFixture();
    defer snap.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    _ = frame.lines(&table, snap);
    table.click(testing.allocator, snap, frame.list, .{ .program = 0 });
    _ = frame.lines(&table, snap);
    table.click(testing.allocator, snap, frame.list, .{ .program = 0, .row = 0 });
    _ = frame.lines(&table, snap);

    table.click(testing.allocator, snap, frame.list, .{ .program = 0, .row = 0, .flow = 1 });
    try testing.expectEqual(Inspected{ .flow = .{ .row = 0, .flow = 1 } }, table.inspected());
    // Still open at both levels: a Flow click that closed the list it was
    // clicked in would move the row out from under the cursor.
    try testing.expectEqual(@as(usize, 5), frame.lines(&table, snap).len);
    try testing.expect(table.isSelected(.{ .program = 0, .row = 0, .flow = 1 }));
    try testing.expect(!table.isSelected(.{ .program = 0, .row = 0, .flow = 0 }));
    try testing.expect(!table.isSelected(.{ .program = 0, .row = 0 }));
}

test "a Program stays open, and stays inspected, as instances come and go" {
    const before = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" },
    }, &.{});
    defer before.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    _ = frame.lines(&table, before);
    table.click(testing.allocator, before, frame.list, .{ .program = 0 });

    // A second instance starts. It is the same Program — keyed by the identity
    // they share, not by whoever happened to be running when it was opened.
    const after = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" },
        .{ .pid = 9, .create_time = 9, .name = "C:\\a.exe" },
    }, &.{});
    defer after.release();
    try testing.expectEqual(@as(usize, 3), frame.lines(&table, after).len);
    try testing.expectEqual(Inspected{ .program = 0 }, table.inspected());
}

test "the selection follows its Flow when the next Snapshot moves it" {
    const before = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{ testFlow(1000), testFlow(1001), testFlow(1002) }},
    );
    defer before.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);
    _ = frame.lines(&table, before);
    table.click(testing.allocator, before, frame.list, .{ .program = 0, .row = 0, .flow = 2 });

    // The first Flow closed and was removed, so every later one shifts up by
    // one index. Following the index would now inspect the wrong conversation.
    const after = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{ testFlow(1001), testFlow(1002) }},
    );
    defer after.release();
    _ = frame.lines(&table, after);
    try testing.expectEqual(Inspected{ .flow = .{ .row = 0, .flow = 1 } }, table.inspected());
}

test "a Flow that ends leaves its own instance inspected" {
    const before = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{ testFlow(1000), testFlow(1001) }},
    );
    defer before.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);
    _ = frame.lines(&table, before);
    table.click(testing.allocator, before, frame.list, .{ .program = 0, .row = 0, .flow = 1 });

    // Closed, Lingered, and finally dropped: the Info View falls back to the
    // instance rather than emptying itself out from under the reader.
    const after = try testSnapshot(
        &.{.{ .pid = 1, .create_time = 1, .name = "C:\\a.exe" }},
        &.{&.{testFlow(1000)}},
    );
    defer after.release();
    _ = frame.lines(&table, after);
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
}

test "a Program the Eviction cap emptied stops being inspected" {
    const before = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 500 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\gone.exe", .recv_rate = 100 },
    }, &.{});
    defer before.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    _ = frame.lines(&table, before);
    const gone: u32 = for (frame.list, 0..) |p, i| {
        if (p.represents == 1) break @intCast(i);
    } else return error.ProgramNotFound;
    table.click(testing.allocator, before, frame.list, .{ .program = gone });

    const after = try testSnapshot(&.{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 500 },
    }, &.{});
    defer after.release();
    _ = frame.lines(&table, after);
    // Nothing left to inspect, and above all not whichever Program inherited
    // that index.
    try testing.expectEqual(Inspected.nothing, table.inspected());
}

test "an open, inspected instance survives its identity arriving" {
    // A placeholder: traffic reached the Engine before the process rundown
    // named it, so half its row key is still zero (snapshot.Row), and it
    // shares a Program with nobody until it has a name.
    const before = try testSnapshot(
        &.{.{ .pid = 7, .create_time = 0, .name = "" }},
        &.{&.{testFlow(1000)}},
    );
    defer before.release();
    var frame: Frame = .{};
    defer frame.deinit();
    var table: Table = .{};
    defer table.deinit(testing.allocator);

    _ = frame.lines(&table, before);
    table.click(testing.allocator, before, frame.list, .{ .program = 0 });
    _ = frame.lines(&table, before);
    table.click(testing.allocator, before, frame.list, .{ .program = 0, .row = 0 });
    try testing.expectEqual(@as(usize, 3), frame.lines(&table, before).len);

    // The Engine adopts the placeholder in place — same row, same totals, new
    // key, and now a Program named after it. The instance keeps the Flows it
    // had open and stays the thing being inspected: it is the same process the
    // whole way through.
    const after = try testSnapshot(
        &.{.{ .pid = 7, .create_time = 777, .name = "C:\\b.exe" }},
        &.{&.{testFlow(1000)}},
    );
    defer after.release();
    // The Program is new, so it starts closed; opening it shows the instance
    // still open beneath.
    _ = frame.lines(&table, after);
    table.toggleProgram(testing.allocator, frame.list[0]);
    try testing.expectEqual(@as(usize, 3), frame.lines(&table, after).len);
    try testing.expectEqual(Inspected{ .process = 0 }, table.inspected());
}
