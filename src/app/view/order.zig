//! The Ledger's order, at both of the levels that have one: the Programs, and
//! the instances within each of them.
//!
//! Sorting a live table by a live number is a trap the UI prototype walked
//! into: rows swap places while speeds jitter, and a click resolves against
//! the previous frame's layout, so you select the wrong row. So the order is
//! *frozen* — recomputed on a 1.5 s beat, and held between beats while the
//! numbers inside the rows keep moving.
//!
//! Holding an order across Snapshots needs a name for "the same thing as last
//! time". For an instance that is the engine's own row key (pid, CreateTime) —
//! see `snapshot.Row.create_time`; for a Program it is the identity hash its
//! instances grouped by (programs.zig). Everything is addressed by index into
//! the Snapshot, so nothing here outlives the one the caller is holding.

const std = @import("std");
const engine = @import("engine");
const format = @import("format.zig");
const programs = @import("programs.zig");

const snapshot = engine.snapshot;

/// The sortable columns. Every column of the Ledger but PID, which the layout
/// lock (issue #10) leaves unsortable on purpose: a table ordered by PID is
/// ordered by process start time, which answers no question this window is
/// asked.
pub const Field = enum { name, down, up, down_total, up_total };
pub const Direction = enum { ascending, descending };

/// The beat the order is recomputed on. The spec allows 1–2 s; the middle of
/// that is slow enough that rows sit still while you aim at one, and fast
/// enough that a process that just went busy does not feel stuck at the bottom.
pub const resort_interval_ms: u64 = 1_500;

/// One Process Row, across Snapshots.
pub const Key = struct { pid: u32, create_time: u64 };

fn keyOf(row: snapshot.Row) Key {
    return .{ .pid = row.pid, .create_time = row.create_time };
}

/// Every ordering is a total order, so the same rows always come out the same
/// way: ties fall back to the row key, which no two live rows share.
fn keyOrder(a: snapshot.Row, b: snapshot.Row) bool {
    if (a.pid != b.pid) return a.pid < b.pid;
    return a.create_time < b.create_time;
}

pub const Ordering = struct {
    field: Field = .down,
    direction: Direction = .descending,
    /// Where each Program sat at the last re-sort, by identity hash
    /// (programs.zig). The Ledger's top level is Programs, so this is the one
    /// that decides what the reader is looking at.
    program_ranks: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    /// Where each row sat at the last re-sort, within its own Program. This
    /// is what freezes the display: between beats things are sorted by these,
    /// not by their (still moving) values.
    ranks: std.AutoHashMapUnmanaged(Key, u32) = .empty,
    /// Null until the first sort — the first frame is sorted, not left in
    /// whatever order the Snapshot happened to arrive in.
    last_resort_ms: ?u64 = null,
    /// Reused across frames: the display order, as indices into the Programs.
    order: std.ArrayList(u32) = .empty,

    pub fn deinit(self: *Ordering, gpa: std.mem.Allocator) void {
        self.program_ranks.deinit(gpa);
        self.ranks.deinit(gpa);
        self.order.deinit(gpa);
    }

    /// A column header was clicked. The re-sort happens on the next frame
    /// rather than at the next beat — a click that appears to do nothing for a
    /// second and a half reads as a broken table.
    pub fn sortBy(self: *Ordering, field: Field, direction: Direction) void {
        self.field = field;
        self.direction = direction;
        self.last_resort_ms = null;
    }

    /// The Programs in display order, as indices into `list`, with each
    /// Program's members sorted in place. Cheap enough to call every frame and
    /// stable when it is: between beats this only re-applies the frozen ranks,
    /// so the answer does not change while the values do.
    ///
    /// Both levels move on the same beat. Re-sorting them on separate clocks
    /// would have a Program hold still while its instances shuffled inside it,
    /// which is the same lie the frozen order exists to prevent.
    pub fn display(
        self: *Ordering,
        gpa: std.mem.Allocator,
        list: []programs.Program,
        rows: []const snapshot.Row,
        now_ms: u64,
    ) []const u32 {
        const buf = self.fill(gpa, list.len);
        const resorting = self.due(now_ms);
        if (resorting) {
            self.last_resort_ms = now_ms;
            // Every Program re-ranks its own members into this map below; it
            // is emptied once, here, so ranks from rows that have since gone
            // do not outlive the beat.
            self.ranks.clearRetainingCapacity();
            std.mem.sortUnstable(u32, buf, ProgramSort{
                .list = list,
                .rows = rows,
                .field = self.field,
                .direction = self.direction,
            }, ProgramSort.lessThan);
            self.recordProgramRanks(gpa, list, buf);
        } else {
            std.mem.sortUnstable(u32, buf, ProgramRankSort{
                .list = list,
                .rows = rows,
                .ranks = &self.program_ranks,
            }, ProgramRankSort.lessThan);
        }

        for (list) |p| self.sortMembers(gpa, p.members, rows, resorting);
        return buf;
    }

    /// One Program's instances, on the same beat as the Programs themselves.
    fn sortMembers(
        self: *Ordering,
        gpa: std.mem.Allocator,
        members: []u32,
        rows: []const snapshot.Row,
        resorting: bool,
    ) void {
        if (resorting) {
            std.mem.sortUnstable(u32, members, FieldSort{
                .rows = rows,
                .field = self.field,
                .direction = self.direction,
            }, FieldSort.lessThan);
            self.recordRanks(gpa, rows, members);
        } else {
            std.mem.sortUnstable(u32, members, RankSort{
                .rows = rows,
                .ranks = &self.ranks,
            }, RankSort.lessThan);
        }
    }

    fn due(self: Ordering, now_ms: u64) bool {
        const last = self.last_resort_ms orelse return true;
        return now_ms -| last >= resort_interval_ms;
    }

    /// The identity permutation over the current rows, ready to sort in place.
    fn fill(self: *Ordering, gpa: std.mem.Allocator, count: usize) []u32 {
        self.order.clearRetainingCapacity();
        // Under memory pressure the table shows the rows it has room for: a
        // short table is a degraded view, and a crash is no view at all.
        const n = if (self.order.ensureTotalCapacity(gpa, count))
            count
        else |_|
            @min(count, self.order.capacity);
        for (0..n) |i| self.order.appendAssumeCapacity(@intCast(i));
        return self.order.items;
    }

    /// Freeze the Program order just computed.
    fn recordProgramRanks(
        self: *Ordering,
        gpa: std.mem.Allocator,
        list: []const programs.Program,
        order: []const u32,
    ) void {
        self.program_ranks.ensureTotalCapacity(gpa, @intCast(order.len)) catch return;
        self.program_ranks.clearRetainingCapacity();
        for (order, 0..) |at, place|
            self.program_ranks.putAssumeCapacity(list[at].key, @intCast(place));
    }

    /// Freeze one Program's member order. Ranks are per Program but share one
    /// map — a row belongs to exactly one Program, so its key appears once.
    /// The map is emptied once at the top of the beat, in `display`, rather
    /// than here: emptying it per Program would wipe the one before.
    fn recordRanks(
        self: *Ordering,
        gpa: std.mem.Allocator,
        rows: []const snapshot.Row,
        order: []const u32,
    ) void {
        // On memory pressure this Program's rows go unranked for the beat and
        // sort to the bottom of their own Program, where a newcomer sits; the
        // next beat tries again. Only this Program is affected — the ones
        // already recorded keep the places they were just given.
        self.ranks.ensureUnusedCapacity(gpa, @intCast(order.len)) catch return;
        for (order, 0..) |row_idx, place|
            self.ranks.putAssumeCapacity(keyOf(rows[row_idx]), @intCast(place));
    }
};

/// The beat, at the top level: sort Programs by what their row actually
/// shows, which is the sum of their instances — not the busiest one of them.
/// A Program running eight quiet instances is busier than one running a single
/// middling one, and the number on the row says so.
const ProgramSort = struct {
    list: []const programs.Program,
    rows: []const snapshot.Row,
    field: Field,
    direction: Direction,

    fn lessThan(self: ProgramSort, a: u32, b: u32) bool {
        const pa = self.list[a];
        const pb = self.list[b];
        return switch (self.compare(pa, pb)) {
            .lt => self.direction == .ascending,
            .gt => self.direction == .descending,
            // Ties fall to the row the Program is named by, so the same
            // Programs always come out the same way.
            .eq => keyOrder(self.rows[pa.represents], self.rows[pb.represents]),
        };
    }

    fn compare(self: ProgramSort, a: programs.Program, b: programs.Program) std.math.Order {
        return switch (self.field) {
            .name => std.ascii.orderIgnoreCase(
                format.processName(self.rows[a.represents].name),
                format.processName(self.rows[b.represents].name),
            ),
            .down => std.math.order(a.recv_rate, b.recv_rate),
            .up => std.math.order(a.sent_rate, b.sent_rate),
            .down_total => format.compareVolume(programs.volume(a, .down), programs.volume(b, .down)),
            .up_total => format.compareVolume(programs.volume(a, .up), programs.volume(b, .up)),
        };
    }
};

/// Between beats, at the top level: sort Programs by where they already were.
const ProgramRankSort = struct {
    list: []const programs.Program,
    rows: []const snapshot.Row,
    ranks: *const std.AutoHashMapUnmanaged(u64, u32),

    fn lessThan(self: ProgramRankSort, a: u32, b: u32) bool {
        const ra = self.rank(self.list[a]);
        const rb = self.rank(self.list[b]);
        if (ra != rb) return ra < rb;
        return keyOrder(self.rows[self.list[a].represents], self.rows[self.list[b].represents]);
    }

    /// Where this Program sat at the last beat, or the bottom — which is where
    /// a Program that has only just started belongs until a beat places it.
    fn rank(self: ProgramRankSort, p: programs.Program) u32 {
        return self.ranks.get(p.key) orelse std.math.maxInt(u32);
    }
};

/// The beat: sort by what the column actually shows.
const FieldSort = struct {
    rows: []const snapshot.Row,
    field: Field,
    direction: Direction,

    fn lessThan(self: FieldSort, a: u32, b: u32) bool {
        const ra = self.rows[a];
        const rb = self.rows[b];
        return switch (self.compare(ra, rb)) {
            .lt => self.direction == .ascending,
            .gt => self.direction == .descending,
            .eq => keyOrder(ra, rb),
        };
    }

    fn compare(self: FieldSort, a: snapshot.Row, b: snapshot.Row) std.math.Order {
        return switch (self.field) {
            // By what the cell says — the exe name, not the path it sits in.
            .name => std.ascii.orderIgnoreCase(
                format.processName(a.name),
                format.processName(b.name),
            ),
            .down => std.math.order(a.recv_rate, b.recv_rate),
            .up => std.math.order(a.sent_rate, b.sent_rate),
            // By what the cell says here too: a totals cell shows bytes, or
            // ICMP messages when messages are all the row moved, and the
            // column has to rank the one it is displaying (format.zig).
            .down_total => format.compareVolume(
                format.rowVolume(a, .down),
                format.rowVolume(b, .down),
            ),
            .up_total => format.compareVolume(
                format.rowVolume(a, .up),
                format.rowVolume(b, .up),
            ),
        };
    }
};

/// Between beats: sort by where the rows already were.
const RankSort = struct {
    rows: []const snapshot.Row,
    ranks: *const std.AutoHashMapUnmanaged(Key, u32),

    fn lessThan(self: RankSort, a: u32, b: u32) bool {
        const ra = self.rows[a];
        const rb = self.rows[b];
        if (self.rank(ra) != self.rank(rb)) return self.rank(ra) < self.rank(rb);
        return keyOrder(ra, rb);
    }

    /// Where this row sat at the last beat, or the bottom — which is where a
    /// newcomer belongs until a beat places it properly.
    ///
    /// A row whose identity arrives is not a case here: it changes Program at
    /// the same moment (programs.zig keys a placeholder by its row key), so it
    /// is the *Program* that is new, and `ProgramRankSort` is where that
    /// lands.
    fn rank(self: RankSort, row: snapshot.Row) u32 {
        return self.ranks.get(keyOf(row)) orelse std.math.maxInt(u32);
    }
};

const testing = std.testing;

/// Whatever else it is, a display order is a permutation: every row shown
/// exactly once. A dropped row is a process that vanished from the monitor.
fn expectPermutation(order: []const u32, row_count: usize) !void {
    try testing.expectEqual(row_count, order.len);
    var seen: [32]bool = @splat(false);
    for (order) |i| {
        try testing.expect(i < row_count);
        try testing.expect(!seen[i]);
        seen[i] = true;
    }
}

/// The display, as the exe names it puts on screen, top first — one name per
/// Program, which is what the Ledger's top level lists. Rows that share an
/// identity are one entry; every test row below has a name of its own unless
/// it is testing the grouping itself.
///
/// The Programs are built and dropped inside this call: the names it returns
/// are the caller's rows, not the grouping's.
fn names(gpa: std.mem.Allocator, o: *Ordering, rows: []const snapshot.Row, now_ms: u64) ![]const []const u8 {
    var grouped: programs.Programs = .{};
    defer grouped.deinit(gpa);
    const list = grouped.build(gpa, rows);

    const order = o.display(gpa, list, rows, now_ms);
    try expectPermutation(order, list.len);
    const out = try gpa.alloc([]const u8, order.len);
    for (order, out) |at, *dst| dst.* = format.processName(rows[list[at].represents].name);
    return out;
}

/// The instances of one Program, in the order they sit under it.
fn instances(gpa: std.mem.Allocator, o: *Ordering, rows: []const snapshot.Row, now_ms: u64) ![]const u32 {
    var grouped: programs.Programs = .{};
    defer grouped.deinit(gpa);
    const list = grouped.build(gpa, rows);
    _ = o.display(gpa, list, rows, now_ms);
    try testing.expectEqual(@as(usize, 1), list.len);
    return gpa.dupe(u32, list[0].members);
}

fn expectOrder(expected: []const []const u8, actual: []const []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try testing.expectEqualStrings(want, got);
}

test "the first frame is already sorted — no unsorted flash on open" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    const rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\quiet.exe", .recv_rate = 10 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\busy.exe", .recv_rate = 900 },
    };

    const shown = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(shown);
    try expectOrder(&.{ "busy.exe", "quiet.exe" }, shown);
}

test "rows hold their place while speeds jitter, and move on the beat" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    var rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 100 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\b.exe", .recv_rate = 50 },
    };

    const first = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(first);
    try expectOrder(&.{ "a.exe", "b.exe" }, first);

    // b overtakes a by a mile. The order must not budge — this is the frame
    // where the prototype's live re-sort made rows jump under the cursor.
    rows[0].recv_rate = 10;
    rows[1].recv_rate = 900;
    const frozen = try names(testing.allocator, &o, &rows, 100);
    defer testing.allocator.free(frozen);
    try expectOrder(&.{ "a.exe", "b.exe" }, frozen);

    // Still frozen right up to the beat...
    const still = try names(testing.allocator, &o, &rows, resort_interval_ms - 1);
    defer testing.allocator.free(still);
    try expectOrder(&.{ "a.exe", "b.exe" }, still);

    // ...and only then does it catch up.
    const beat = try names(testing.allocator, &o, &rows, resort_interval_ms);
    defer testing.allocator.free(beat);
    try expectOrder(&.{ "b.exe", "a.exe" }, beat);
}

test "clicking a column re-sorts at once, not at the next beat" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    const rows = [_]snapshot.Row{
        .{ .pid = 7, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 900, .sent = 1 },
        .{ .pid = 3, .create_time = 2, .name = "C:\\b.exe", .recv_rate = 10, .sent = 500 },
    };

    const by_down = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(by_down);
    try expectOrder(&.{ "a.exe", "b.exe" }, by_down);

    o.sortBy(.up_total, .descending);
    const by_up_total = try names(testing.allocator, &o, &rows, 1);
    defer testing.allocator.free(by_up_total);
    try expectOrder(&.{ "b.exe", "a.exe" }, by_up_total);

    o.sortBy(.name, .ascending);
    const by_name = try names(testing.allocator, &o, &rows, 3);
    defer testing.allocator.free(by_name);
    try expectOrder(&.{ "a.exe", "b.exe" }, by_name);
}

test "a Program is ranked by its instances together, not by its busiest one" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    // Three quiet instances of one program against a single middling process.
    // Ranking a Program by its busiest member would put `one.exe` on top,
    // while the row beside it reads 300 against 250 — a column has to order
    // what it shows (format.compareVolume, issue #28).
    const rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\many.exe", .recv_rate = 100 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\one.exe", .recv_rate = 250 },
        .{ .pid = 3, .create_time = 3, .name = "C:\\many.exe", .recv_rate = 100 },
        .{ .pid = 4, .create_time = 4, .name = "C:\\many.exe", .recv_rate = 100 },
    };

    const shown = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(shown);
    try expectOrder(&.{ "many.exe", "one.exe" }, shown);
}

test "instances hold their order under their Program, and move on the beat" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    var rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 100 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\a.exe", .recv_rate = 50 },
    };

    const first = try instances(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(first);
    try testing.expectEqualSlices(u32, &.{ 0, 1 }, first);

    // The second instance overtakes the first. Instances freeze on the same
    // beat as the Programs above them — a Program holding still while its own
    // rows shuffled inside it would be the same lie, one level down.
    rows[0].recv_rate = 10;
    rows[1].recv_rate = 900;
    const frozen = try instances(testing.allocator, &o, &rows, 100);
    defer testing.allocator.free(frozen);
    try testing.expectEqualSlices(u32, &.{ 0, 1 }, frozen);

    const beat = try instances(testing.allocator, &o, &rows, resort_interval_ms);
    defer testing.allocator.free(beat);
    try testing.expectEqualSlices(u32, &.{ 1, 0 }, beat);
}

test "a totals column ranks messages among the rows that moved no bytes" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    // An ICMP Flow moves messages and no bytes anyone can count (CONTEXT.md
    // "ICMP Message Count"), so its row's totals cells show "N msgs".
    const three = [_]snapshot.Flow{icmpFlow(3)};
    const nine = [_]snapshot.Flow{icmpFlow(9)};
    const rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\quiet.exe" },
        .{ .pid = 2, .create_time = 2, .name = "C:\\ping3.exe", .flows = &three },
        .{ .pid = 3, .create_time = 3, .name = "C:\\downloader.exe", .recv = 9000 },
        .{ .pid = 4, .create_time = 4, .name = "C:\\ping9.exe", .flows = &nine },
    };

    o.sortBy(.down_total, .descending);
    const shown = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(shown);
    // Bytes outrank messages — they are not convertible, so the column ranks
    // them by kind — and the busier pinger still leads the quieter one.
    try expectOrder(&.{ "downloader.exe", "ping9.exe", "ping3.exe", "quiet.exe" }, shown);
}

/// An ICMP Flow that has received `msgs` messages and, like every ICMP Flow,
/// no bytes.
fn icmpFlow(msgs: u64) snapshot.Flow {
    return .{
        .proto = .icmp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .generation = 1,
        .msgs_recv = msgs,
    };
}

test "a process that starts between beats lands at the bottom, and is never lost" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    const before = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 100 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\b.exe", .recv_rate = 50 },
    };
    const first = try names(testing.allocator, &o, &before, 0);
    defer testing.allocator.free(first);
    try expectOrder(&.{ "a.exe", "b.exe" }, first);

    // A newcomer, busier than both — but the ranked rows keep their places
    // until the beat, so it waits at the bottom rather than shoving them down.
    const after = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 100 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\b.exe", .recv_rate = 50 },
        .{ .pid = 3, .create_time = 3, .name = "C:\\new.exe", .recv_rate = 5000 },
    };
    const with_new = try names(testing.allocator, &o, &after, 100);
    defer testing.allocator.free(with_new);
    try expectOrder(&.{ "a.exe", "b.exe", "new.exe" }, with_new);

    const beat = try names(testing.allocator, &o, &after, resort_interval_ms);
    defer testing.allocator.free(beat);
    try expectOrder(&.{ "new.exe", "a.exe", "b.exe" }, beat);
}

test "a row the Eviction cap took leaves the rest where they were" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    const before = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 300 },
        .{ .pid = 2, .create_time = 2, .name = "C:\\gone.exe", .recv_rate = 200 },
        .{ .pid = 3, .create_time = 3, .name = "C:\\c.exe", .recv_rate = 100 },
    };
    const first = try names(testing.allocator, &o, &before, 0);
    defer testing.allocator.free(first);
    try expectOrder(&.{ "a.exe", "gone.exe", "c.exe" }, first);

    const after = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 300 },
        .{ .pid = 3, .create_time = 3, .name = "C:\\c.exe", .recv_rate = 100 },
    };
    const survivors = try names(testing.allocator, &o, &after, 100);
    defer testing.allocator.free(survivors);
    try expectOrder(&.{ "a.exe", "c.exe" }, survivors);
}

test "two instances of a reused PID hold separate places" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    // Same PID, two instances — only CreateTime tells them apart (issue #21).
    var rows = [_]snapshot.Row{
        .{ .pid = 100, .create_time = 111, .name = "C:\\old.exe", .exited = true, .recv_rate = 10 },
        .{ .pid = 100, .create_time = 500, .name = "C:\\new.exe", .recv_rate = 20 },
    };
    const first = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(first);
    try expectOrder(&.{ "new.exe", "old.exe" }, first);

    // Flip the rates. If the two shared one identity they would share one
    // rank, and the tie-break would surface the older instance first.
    rows[0].recv_rate = 99;
    rows[1].recv_rate = 1;
    const frozen = try names(testing.allocator, &o, &rows, 100);
    defer testing.allocator.free(frozen);
    try expectOrder(&.{ "new.exe", "old.exe" }, frozen);
}

test "a row joins its Program when its identity finally arrives" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    // A placeholder: traffic reached the Engine before the process rundown
    // named it, so its half of the row key is still zero (snapshot.Row). With
    // no identity it shares a Program with nobody (programs.zig).
    var rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = "C:\\a.exe", .recv_rate = 300 },
        .{ .pid = 2, .create_time = 0, .name = "", .recv_rate = 200 },
        .{ .pid = 3, .create_time = 3, .name = "C:\\c.exe", .recv_rate = 100 },
    };
    const first = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(first);
    try expectOrder(&.{ "a.exe", format.unnamed, "c.exe" }, first);

    // The identity lands and the Engine adopts the placeholder in place: same
    // row, same totals — but a *different* Program, because it now shares an
    // identity it did not have before. So it arrives as a newcomer and waits
    // at the bottom, like any Program the beat has not placed yet...
    rows[1].create_time = 777;
    rows[1].name = "C:\\b.exe";
    const adopted = try names(testing.allocator, &o, &rows, 100);
    defer testing.allocator.free(adopted);
    try expectOrder(&.{ "a.exe", "c.exe", "b.exe" }, adopted);

    // ...and the next beat puts it where its traffic says it belongs.
    const beat = try names(testing.allocator, &o, &rows, resort_interval_ms);
    defer testing.allocator.free(beat);
    try expectOrder(&.{ "a.exe", "b.exe", "c.exe" }, beat);
}

test "equal values still order the same way every frame" {
    var o: Ordering = .{};
    defer o.deinit(testing.allocator);
    // Idle machine: every row's Down is zero, so the tie-break decides.
    const rows = [_]snapshot.Row{
        .{ .pid = 9, .create_time = 1, .name = "C:\\c.exe" },
        .{ .pid = 4, .create_time = 1, .name = "C:\\a.exe" },
        .{ .pid = 4, .create_time = 2, .name = "C:\\b.exe" },
    };
    const first = try names(testing.allocator, &o, &rows, 0);
    defer testing.allocator.free(first);
    try expectOrder(&.{ "a.exe", "b.exe", "c.exe" }, first);

    o.sortBy(.down, .descending);
    const again = try names(testing.allocator, &o, &rows, 1);
    defer testing.allocator.free(again);
    try expectOrder(&.{ "a.exe", "b.exe", "c.exe" }, again);
}
