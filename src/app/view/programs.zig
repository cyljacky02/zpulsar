//! What the Ledger's top level lists: the Programs, and what each one's
//! Process Rows add up to.
//!
//! A machine runs eight instances of one terminal, and eight top-level rows
//! that re-sort against each other is a list nobody can hold still in their
//! head. So the instances are grouped under the identity they share, and the
//! group carries their sums.
//!
//! The identity is the one the Ledger already *displays*, not the executable
//! behind it: a Process Row that is a single service groups under that
//! service, so Service Attribution survives the grouping (issue #25). Group by
//! exe and `Dnscache` and `Windows Update` collapse back into one
//! `svchost.exe`, which is the thing that ticket existed to take apart.
//!
//! Grouping is display only — no Engine state, no Snapshot change. Programs
//! are rebuilt from each Snapshot and index into it, so nothing here outlives
//! the Snapshot the caller is holding.

const std = @import("std");
const engine = @import("engine");
const format = @import("format.zig");

const snapshot = engine.snapshot;

/// One Program: the identity a set of Process Rows share, and what they add
/// up to. Its members are indices into the Snapshot it was built from.
pub const Program = struct {
    /// The identity, hashed — what survives a Snapshot, since the text behind
    /// it is arena-owned by one and the next Snapshot brings its own copy.
    key: u64,
    /// The member this row is *drawn* from. Every member shares the identity,
    /// so any of them can name it; when the first one exits the label does not
    /// change, only which row it was read from.
    represents: u32,
    /// Indices into `Snapshot.rows`, in the order the Snapshot had them until
    /// the Ledger's ordering sorts them (order.zig).
    members: []u32,

    /// The members' sums. Rates and bytes add up because they are the same
    /// unit; messages are counted separately and never folded in (CONTEXT.md
    /// "ICMP Message Count").
    recv_rate: u64 = 0,
    sent_rate: u64 = 0,
    recv: u64 = 0,
    sent: u64 = 0,
    msgs_recv: u64 = 0,
    msgs_sent: u64 = 0,
    /// How many Flows expand beneath this Program, across every instance.
    flows: usize = 0,
    /// Every instance has exited. One still running means the Program is
    /// still running, so this is an `and` over the members, not an `or`.
    exited: bool = true,
};

/// A Program's In-session Totals, under the same rule a single row follows:
/// bytes, unless it moved none and its Flows have messages.
pub fn volume(p: Program, dir: format.Direction) format.Volume {
    return format.volumeOf(p.recv, p.sent, p.msgs_recv, p.msgs_sent, dir);
}

/// The Programs of one Snapshot, rebuilt each frame into reused storage.
pub const Programs = struct {
    list: std.ArrayList(Program) = .empty,
    /// Every Program's members, back to back; each Program holds a slice.
    /// One array so grouping costs one allocation rather than one per
    /// Program, on a path that runs every frame.
    membership: std.ArrayList(u32) = .empty,
    /// Where each Program's slice starts in `membership`, and how many members
    /// were counted for it. Kept beside the Programs rather than inside them:
    /// the second pass has to be able to check that it is filling a slot that
    /// was actually counted, and a Program that reached the reader should
    /// carry nothing but what it means.
    starts: std.ArrayList(u32) = .empty,
    counts: std.ArrayList(u32) = .empty,
    /// Identity hash to index in `list`, for the current build only.
    seen: std.AutoHashMapUnmanaged(u64, u32) = .empty,

    pub fn deinit(self: *Programs, gpa: std.mem.Allocator) void {
        self.list.deinit(gpa);
        self.membership.deinit(gpa);
        self.starts.deinit(gpa);
        self.counts.deinit(gpa);
        self.seen.deinit(gpa);
    }

    /// Group `rows` and sum them. Valid until the next call, and only against
    /// the Snapshot the rows came from.
    pub fn build(self: *Programs, gpa: std.mem.Allocator, rows: []const snapshot.Row) []Program {
        self.list.clearRetainingCapacity();
        self.membership.clearRetainingCapacity();
        self.starts.clearRetainingCapacity();
        self.counts.clearRetainingCapacity();
        self.seen.clearRetainingCapacity();

        // Two passes: the first counts members per Program so the second can
        // hand out exact slices of one array. Growing per-Program lists would
        // allocate per group, every frame.
        for (rows, 0..) |row, i| self.tally(gpa, row, @intCast(i));
        self.layout(gpa);
        for (rows, 0..) |row, i| self.place(row, @intCast(i));
        return self.list.items;
    }

    /// First pass: find or open this row's Program and add its numbers.
    fn tally(self: *Programs, gpa: std.mem.Allocator, row: snapshot.Row, index: u32) void {
        const key = keyOf(row);
        const at = self.seen.get(key) orelse blk: {
            const at: u32 = @intCast(self.list.items.len);
            // No room for another Program: this row is left out of the table
            // for this frame. A short table is a degraded view and the next
            // Snapshot tries again; the alternative is no view at all.
            self.list.append(gpa, .{ .key = key, .represents = index, .members = &.{} }) catch
                return;
            self.counts.append(gpa, 0) catch {
                _ = self.list.pop();
                return;
            };
            self.seen.put(gpa, key, at) catch {
                _ = self.list.pop();
                _ = self.counts.pop();
                return;
            };
            break :blk at;
        };
        const p = &self.list.items[at];
        p.recv_rate += row.recv_rate;
        p.sent_rate += row.sent_rate;
        p.recv += row.recv;
        p.sent += row.sent;
        p.flows += row.flows.len;
        for (row.flows) |f| {
            p.msgs_recv += f.msgs_recv;
            p.msgs_sent += f.msgs_sent;
        }
        // Exited rows persist all session (CONTEXT.md "Process Row"); the
        // Program is only gone once every instance of it is.
        if (!row.exited) p.exited = false;
        self.counts.items[at] += 1;
    }

    /// Between the passes: give every Program an empty slice at the offset its
    /// counted members will fill.
    fn layout(self: *Programs, gpa: std.mem.Allocator) void {
        var total: usize = 0;
        for (self.counts.items) |count| total += count;

        if (self.reserve(gpa, total)) |_| {} else |_| {
            // No room to record membership: every Program keeps its numbers
            // and shows no instances, which is visibly degraded rather than
            // silently wrong.
            for (self.list.items) |*p| p.members = &.{};
            self.counts.clearRetainingCapacity();
            return;
        }

        var at: u32 = 0;
        for (self.list.items, self.counts.items, self.starts.items) |*p, count, *start| {
            start.* = at;
            p.members = self.membership.items[at..][0..0];
            at += count;
        }
    }

    fn reserve(self: *Programs, gpa: std.mem.Allocator, total: usize) !void {
        try self.membership.resize(gpa, total);
        try self.starts.resize(gpa, self.list.items.len);
    }

    /// Second pass: put each row in its Program's slice, in Snapshot order.
    ///
    /// Bounded by the count the first pass took, not by trust: the two passes
    /// can disagree — a Program that failed to open on its first row can
    /// succeed on a later one, leaving `seen` naming a Program that never
    /// counted the earlier row — and a slice filled past what was counted for
    /// it would write over the next Program's members, or off the end.
    fn place(self: *Programs, row: snapshot.Row, index: u32) void {
        if (self.counts.items.len == 0) return; // `layout` gave up on membership
        const at = self.seen.get(keyOf(row)) orelse return;
        const p = &self.list.items[at];
        if (p.members.len >= self.counts.items[at]) return;
        self.membership.items[self.starts.items[at] + p.members.len] = index;
        p.members.len += 1;
    }
};

/// What a Process Row groups by: the identity the Ledger shows for it.
///
/// One hosted service means the row *is* that service (CONTEXT.md "Process
/// Row"), so it groups by the service — that is what keeps a service host's
/// services apart. Everything else groups by its display path. A row with
/// neither has no identity to share and groups alone, under its own row key,
/// until one arrives.
fn keyOf(row: snapshot.Row) u64 {
    if (row.services.len == 1) return hash("svc\x00", row.services[0]);
    if (row.name.len > 0) return hash("exe\x00", row.name);
    return std.hash.Wyhash.hash(0, std.mem.asBytes(&[2]u64{ row.pid, row.create_time }));
}

/// Hashed rather than kept: the identity text is arena-owned by the Snapshot
/// it came from, so holding it would tie a Program to a Snapshot that has been
/// replaced. The tag keeps a service called `chrome.exe` from sharing a
/// Program with the executable of that name.
fn hash(tag: []const u8, text: []const u8) u64 {
    var h: std.hash.Wyhash = .init(0);
    h.update(tag);
    h.update(text);
    return h.final();
}

const testing = std.testing;

fn testRow(pid: u32, name: []const u8) snapshot.Row {
    return .{ .pid = pid, .create_time = pid, .name = name };
}

test "instances of one executable become one Program, and keep their order" {
    const rows = [_]snapshot.Row{
        testRow(1, "C:\\electerm.exe"),
        testRow(2, "C:\\chrome.exe"),
        testRow(3, "C:\\electerm.exe"),
        testRow(4, "C:\\electerm.exe"),
    };
    var grouped: Programs = .{};
    defer grouped.deinit(testing.allocator);
    const programs = grouped.build(testing.allocator, &rows);

    try testing.expectEqual(@as(usize, 2), programs.len);
    // First seen, first listed — the ordering is a later concern (order.zig).
    try testing.expectEqualSlices(u32, &.{ 0, 2, 3 }, programs[0].members);
    try testing.expectEqualSlices(u32, &.{1}, programs[1].members);
    // Two copies of one program in different directories are still one
    // Program: it is named by its exe, the way the table names it.
    try testing.expectEqualStrings("electerm.exe", format.processName(rows[programs[0].represents].name));
}

test "a service host's services stay one Program each" {
    // CONTEXT.md "Process Row": one hosted service means the row *is* that
    // service. Grouping by exe would undo that and put them back in one
    // svchost row (issue #25).
    const host = "C:\\Windows\\System32\\svchost.exe";
    var rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 1, .name = host, .services = &.{"Dnscache"} },
        .{ .pid = 2, .create_time = 2, .name = host, .services = &.{"Windows Update"} },
        .{ .pid = 3, .create_time = 3, .name = host, .services = &.{"Dnscache"} },
        // A host whose services are not known, or which runs several: it has
        // no single service to be, so it groups by its executable.
        .{ .pid = 4, .create_time = 4, .name = host, .services = &.{ "Dhcp", "NlaSvc" } },
    };
    var grouped: Programs = .{};
    defer grouped.deinit(testing.allocator);
    const programs = grouped.build(testing.allocator, &rows);

    try testing.expectEqual(@as(usize, 3), programs.len);
    try testing.expectEqualSlices(u32, &.{ 0, 2 }, programs[0].members);
    try testing.expectEqualSlices(u32, &.{1}, programs[1].members);
    try testing.expectEqualSlices(u32, &.{3}, programs[2].members);
}

test "a Program's numbers are its members' sums" {
    const rows = [_]smallRow{
        .{ .recv_rate = 100, .sent_rate = 10, .recv = 5000, .sent = 500, .flows = 2 },
        .{ .recv_rate = 25, .sent_rate = 5, .recv = 90, .sent = 9, .flows = 1 },
    };
    var built: [2]snapshot.Row = undefined;
    for (&built, rows, 0..) |*dst, src, i| dst.* = src.row(@intCast(i + 1), "C:\\a.exe");
    var flows: [3]snapshot.Flow = @splat(testTcpFlow(0, 0));
    built[0].flows = flows[0..2];
    built[1].flows = flows[2..3];

    var grouped: Programs = .{};
    defer grouped.deinit(testing.allocator);
    const programs = grouped.build(testing.allocator, &built);

    try testing.expectEqual(@as(usize, 1), programs.len);
    const p = programs[0];
    try testing.expectEqual(@as(u64, 125), p.recv_rate);
    try testing.expectEqual(@as(u64, 15), p.sent_rate);
    try testing.expectEqual(@as(u64, 5090), p.recv);
    try testing.expectEqual(@as(u64, 509), p.sent);
    try testing.expectEqual(@as(usize, 3), p.flows);
    try testing.expectEqual(@as(usize, 2), p.members.len);
}

test "a row with no identity yet shares a Program with nobody" {
    // A placeholder's name has not arrived (snapshot.Row), so it has no
    // identity to share — grouping them by their empty name would merge
    // unrelated processes under one row.
    const rows = [_]snapshot.Row{
        .{ .pid = 1, .create_time = 0, .name = "" },
        .{ .pid = 2, .create_time = 0, .name = "" },
        .{ .pid = 3, .create_time = 3, .name = "C:\\a.exe" },
    };
    var grouped: Programs = .{};
    defer grouped.deinit(testing.allocator);
    const programs = grouped.build(testing.allocator, &rows);

    try testing.expectEqual(@as(usize, 3), programs.len);
    try testing.expectEqualSlices(u32, &.{0}, programs[0].members);
    try testing.expectEqualSlices(u32, &.{1}, programs[1].members);
}

test "a Program that moved only messages counts messages" {
    var ping = testIcmpFlow(3, 4);
    var rows = [_]snapshot.Row{
        testRow(1, "C:\\PING.EXE"),
        testRow(2, "C:\\PING.EXE"),
    };
    rows[0].flows = (&ping)[0..1];
    rows[1].flows = (&ping)[0..1];

    var grouped: Programs = .{};
    defer grouped.deinit(testing.allocator);
    const programs = grouped.build(testing.allocator, &rows);

    var buf: [format.msgs_buf_len]u8 = undefined;
    // The rule a totals cell follows everywhere (format.rowVolume), applied to
    // the sums: bytes when there are any, messages when that is all there is.
    try testing.expectEqualStrings("6 msgs", format.volume(&buf, volume(programs[0], .down)));
    try testing.expectEqualStrings("8 msgs", format.volume(&buf, volume(programs[0], .up)));
}

test "a Program is exited only when every instance of it is" {
    var rows = [_]snapshot.Row{
        testRow(1, "C:\\a.exe"),
        testRow(2, "C:\\a.exe"),
        testRow(3, "C:\\gone.exe"),
    };
    rows[0].exited = true;
    rows[2].exited = true;

    var grouped: Programs = .{};
    defer grouped.deinit(testing.allocator);
    const programs = grouped.build(testing.allocator, &rows);
    // One instance still running means the program is still running.
    try testing.expect(!programs[0].exited);
    try testing.expect(programs[1].exited);
}

/// The activity fields a test row varies, so the sums are readable.
const smallRow = struct {
    recv_rate: u64 = 0,
    sent_rate: u64 = 0,
    recv: u64 = 0,
    sent: u64 = 0,
    flows: usize = 0,

    fn row(self: smallRow, pid: u32, name: []const u8) snapshot.Row {
        return .{
            .pid = pid,
            .create_time = pid,
            .name = name,
            .recv_rate = self.recv_rate,
            .sent_rate = self.sent_rate,
            .recv = self.recv,
            .sent = self.sent,
        };
    }
};

fn testTcpFlow(recv: u64, sent: u64) snapshot.Flow {
    return .{
        .proto = .tcp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 1,
        .remote_port = 443,
        .generation = 1,
        .recv = recv,
        .sent = sent,
    };
}

fn testIcmpFlow(msgs_recv: u64, msgs_sent: u64) snapshot.Flow {
    return .{
        .proto = .icmp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .generation = 1,
        .msgs_recv = msgs_recv,
        .msgs_sent = msgs_sent,
    };
}
