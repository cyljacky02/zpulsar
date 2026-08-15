//! What the Info View has to say about the selection: the Process section's
//! fields, the Flow section's, and the activity under each. The panel itself
//! is a right-docked strip of labels (locked layout, issue #10) — everything
//! that decides *which* labels, and what they read, is here, where it can be
//! checked without a device.
//!
//! The view renders whatever the Snapshot has: fields the Engine cannot fill
//! yet are absent rather than blank, and the ones the spec fixed as
//! placeholders say so.

const std = @import("std");
const engine = @import("engine");
const format = @import("format.zig");

const snapshot = engine.snapshot;

/// The most fields any one section produces, and the text they can hold
/// between them: a display path, a hostname and its alias are the long ones.
const max_fields = 12;
const text_capacity = 1024;

/// One labelled line of a section.
pub const Field = struct {
    label: []const u8,
    /// Where this field's text sits in its `Fields` — an offset rather than a
    /// slice, so a `Fields` can be moved or copied without leaving a Field
    /// pointing at where it used to be.
    at: u16,
    len: u16,
    /// Rendered dimmed: a value nobody observed (a Hint), or one the Engine
    /// has nothing to put in.
    dim: bool = false,
};

/// A section's fields and the text behind them, built in place and read the
/// same frame. Fixed-capacity: the Info View is drawn every frame and
/// allocates nothing to do it.
pub const Fields = struct {
    items: [max_fields]Field = undefined,
    count: usize = 0,
    text: [text_capacity]u8 = undefined,
    used: usize = 0,

    pub fn slice(self: *const Fields) []const Field {
        return self.items[0..self.count];
    }

    pub fn value(self: *const Fields, f: Field) []const u8 {
        return self.text[f.at..][0..f.len];
    }

    /// Append one field. Beyond capacity the field is dropped rather than
    /// mangling the ones already there — the panel is a fixed shape and the
    /// long values are all bounded by what the Engine can publish.
    fn add(self: *Fields, label: []const u8, text: []const u8, dim: bool) void {
        if (self.count == self.items.len) return;
        const room = self.text.len - self.used;
        const kept = format.truncate(text, room);
        @memcpy(self.text[self.used..][0..kept.len], kept);
        self.items[self.count] = .{
            .label = label,
            .at = @intCast(self.used),
            .len = @intCast(kept.len),
            .dim = dim,
        };
        self.used += kept.len;
        self.count += 1;
    }
};

/// The Tools section: reserved extension points, **not implemented in v1**
/// (issue #10 resolution). They are rendered inert so the panel's shape is
/// settled now and the per-address tools land in v2 without a redesign.
pub const process_tools = [_][]const u8{ "Open file location", "Copy path" };
pub const flow_tools = [_][]const u8{ "Traceroute", "MTR", "WHOIS", "Copy remote address" };
/// What the reserved entries say for themselves, so nobody reads them as
/// broken buttons.
pub const tools_note = "extension points (v2+)";

/// A Process Row's properties: what it is, where it lives, and how much of
/// the machine's network it is holding open.
pub fn processProperties(out: *Fields, r: snapshot.Row) void {
    var buf: [32]u8 = undefined;
    out.add("Name", format.processName(r.name), r.name.len == 0);
    if (r.evicted_processes) {
        // It owns no PID, no path and no Flows: it is where attribution stops
        // (CONTEXT.md), so those lines are the dash rather than a zero.
        out.add("PID", format.idle, true);
        return;
    }
    out.add("PID", std.fmt.bufPrint(&buf, "{d}", .{r.pid}) catch format.unnamed, false);
    if (r.services.len == 1) {
        out.add("Service", r.services[0], false);
    } else if (r.services.len > 1) {
        addServices(out, r.services);
    }
    // The full path, where the Name line above is only the exe. A row with no
    // identity yet has no path to give, and says nothing rather than repeating
    // the "?" above.
    if (r.name.len > 0) out.add("Path", r.name, false);
    out.add("Flows", std.fmt.bufPrint(&buf, "{d}", .{r.flows.len}) catch format.unnamed, false);
}

/// A Process Row's activity: the whole row, Flows and Linger included.
pub fn processActivity(out: *Fields, r: snapshot.Row) void {
    addRates(out, r.recv_rate, r.sent_rate);
    addTotals(out, format.rowVolume(r, .down), format.rowVolume(r, .up));
}

/// Every service a shared host is running. The names are what makes the row's
/// "N services" fallback checkable, so they are listed rather than counted.
/// The list is what the panel has room for that the row does not.
fn addServices(out: *Fields, services: []const []const u8) void {
    var buf: [text_capacity]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    for (services, 0..) |name, i| {
        if (i > 0) w.writeAll(", ") catch break;
        w.writeAll(name) catch break;
    }
    out.add("Services", w.buffered(), false);
}

/// A Flow's properties: protocol, both endpoints, the name behind the remote
/// one, and the country v1 cannot yet name.
pub fn flowProperties(out: *Fields, f: snapshot.Flow) void {
    var buf: [group_buf_len]u8 = undefined;
    out.add("Protocol", protocol(f.proto), false);
    out.add("Local", format.endpoint(&buf, f, .local), false);
    if (groupName(&buf, f)) |group| out.add("Group", group, false);
    out.add("Remote", format.endpoint(&buf, f, .remote), false);

    // A Hint is evidence, just not attributable (CONTEXT.md), so it renders
    // dimmed behind the source that produced it. Only an observed name — the
    // one the process itself resolved — stands on its own.
    const hint = f.hostname_origin != .observed;
    if (f.remote_hostname) |name| {
        out.add("Remote name", name, hint);
        if (nameSource(f.hostname_origin)) |source| out.add("Name source", source, true);
        // The tail of the CNAME chain: the name the address actually belongs
        // to, behind the one that was asked for.
        if (f.remote_alias) |alias| out.add("Alias", alias, true);
    } else {
        // The endpoint above is already everything known; a blank line would
        // read as a rendering bug rather than as an answer.
        out.add("Remote name", "Unresolved", true);
    }
    // Country is reserved, not missing: the layout keeps the line so the field
    // lands without a redesign once there is a source for it (issue #10).
    out.add("Country", format.idle, true);
}

/// A Flow's activity: what it is moving now, and what it has moved this
/// session — in bytes, or in messages when it is ICMP.
pub fn flowActivity(out: *Fields, f: snapshot.Flow) void {
    addRates(out, f.recv_rate, f.sent_rate);
    addTotals(out, format.flowVolume(f, .down), format.flowVolume(f, .up));
}

/// The two speed lines. ICMP publishes no speeds — there are no byte sizes to
/// build one from — so both come out as the dash, which is what a Snapshot
/// with nothing in those fields honestly means.
fn addRates(out: *Fields, recv_rate: u64, sent_rate: u64) void {
    var buf: [format.rate_buf_len]u8 = undefined;
    out.add("Down rate", format.rate(&buf, recv_rate), recv_rate == 0);
    out.add("Up rate", format.rate(&buf, sent_rate), sent_rate == 0);
}

/// The two In-session Totals lines, each in its own unit.
fn addTotals(out: *Fields, down: format.Volume, up: format.Volume) void {
    var buf: [format.msgs_buf_len]u8 = undefined;
    out.add("Down session", format.volume(&buf, down), format.isIdle(down));
    out.add("Up session", format.volume(&buf, up), format.isIdle(up));
}

/// Where a name came from, or null for one that needs no explaining.
fn nameSource(origin: engine.hostnames.Origin) ?[]const u8 {
    return switch (origin) {
        .observed => null,
        .cache => "resolver cache",
        .reverse => "reverse lookup",
    };
}

/// Room for the widest address plus the longest kind it can be tagged with —
/// the address buffer alone is not enough, and a Group Address that did not
/// fit would drop the very line that explains the Flow (ADR-0004).
const group_buf_len = format.endpoint_buf_len + " (multicast)".len;

/// The Group Address this Flow's datagrams arrived at, and which kind it is.
/// Receive-only: a send addressed to a group already shows it as the remote
/// endpoint, where it belongs.
fn groupName(buf: []u8, f: snapshot.Flow) ?[]const u8 {
    const kind = switch (f.group_kind) {
        .none => return null,
        .multicast => "multicast",
        .broadcast => "broadcast",
    };
    var addr: [format.endpoint_buf_len]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s} ({s})", .{
        format.address(&addr, f.family, f.group_addr, null),
        kind,
    }) catch null;
}

pub fn protocol(p: engine.event.Proto) []const u8 {
    return switch (p) {
        .tcp => "TCP",
        .udp => "UDP",
        .icmp => "ICMP",
    };
}

const testing = std.testing;

/// A Flow of the kind the Info View is mostly asked about: a TCP conversation
/// with a name the process was seen resolving.
fn testFlow() snapshot.Flow {
    var local: [16]u8 = @splat(0);
    local[0..4].* = .{ 192, 168, 1, 10 };
    var remote: [16]u8 = @splat(0);
    remote[0..4].* = .{ 23, 55, 98, 114 };
    return .{
        .proto = .tcp,
        .family = .v4,
        .local_addr = local,
        .remote_addr = remote,
        .local_port = 61204,
        .remote_port = 443,
        .generation = 1,
        .recv = 116_300_000,
        .sent = 926_000,
        .recv_rate = 44_600_000,
        .sent_rate = 355_000,
        .remote_hostname = "cache1-fra2.steamcontent.com",
        .hostname_origin = .observed,
    };
}

const Expected = struct {
    label: []const u8,
    value: []const u8,
    dim: bool = false,
};

fn expectFields(expected: []const Expected, actual: *const Fields) !void {
    const items = actual.slice();
    try testing.expectEqual(expected.len, items.len);
    for (expected, items) |want, got| {
        try testing.expectEqualStrings(want.label, got.label);
        try testing.expectEqualStrings(want.value, actual.value(got));
        try testing.expectEqual(want.dim, got.dim);
    }
}

test "a selected Flow reads out the properties the layout lock fixed" {
    var fields: Fields = .{};
    flowProperties(&fields, testFlow());
    try expectFields(&.{
        .{ .label = "Protocol", .value = "TCP" },
        .{ .label = "Local", .value = "192.168.1.10:61204" },
        .{ .label = "Remote", .value = "23.55.98.114:443" },
        .{ .label = "Remote name", .value = "cache1-fra2.steamcontent.com" },
        // Country is the one field v1 knows it cannot fill: GeoIP is parked
        // (issue #10 resolution), and a blank would read as "no country".
        .{ .label = "Country", .value = format.idle, .dim = true },
    }, &fields);
}

test "a name nobody was seen resolving renders as the Hint it is" {
    // CONTEXT.md "Hint": a name from the resolver cache or a reverse lookup
    // says an address *was* resolved under it, never by whom — so it renders
    // dimmed, behind its source, and never passes for an observation.
    var f = testFlow();
    f.hostname_origin = .reverse;
    var fields: Fields = .{};
    flowProperties(&fields, f);
    try expectFields(&.{
        .{ .label = "Protocol", .value = "TCP" },
        .{ .label = "Local", .value = "192.168.1.10:61204" },
        .{ .label = "Remote", .value = "23.55.98.114:443" },
        .{ .label = "Remote name", .value = "cache1-fra2.steamcontent.com", .dim = true },
        .{ .label = "Name source", .value = "reverse lookup", .dim = true },
        .{ .label = "Country", .value = format.idle, .dim = true },
    }, &fields);

    f.hostname_origin = .cache;
    var cached: Fields = .{};
    flowProperties(&cached, f);
    try testing.expectEqualStrings("Name source", cached.slice()[4].label);
    try testing.expectEqualStrings("resolver cache", cached.value(cached.slice()[4]));
}

test "an unresolved remote says so, instead of leaving the line blank" {
    var f = testFlow();
    f.remote_hostname = null;
    var fields: Fields = .{};
    flowProperties(&fields, f);
    try expectFields(&.{
        .{ .label = "Protocol", .value = "TCP" },
        .{ .label = "Local", .value = "192.168.1.10:61204" },
        .{ .label = "Remote", .value = "23.55.98.114:443" },
        // The endpoint above is everything known; a blank would read as a
        // rendering bug, and there is no source line to name.
        .{ .label = "Remote name", .value = "Unresolved", .dim = true },
        .{ .label = "Country", .value = format.idle, .dim = true },
    }, &fields);
}

test "the alias behind a name is the name the address really belongs to" {
    var f = testFlow();
    f.remote_alias = "steamcontent.com";
    var fields: Fields = .{};
    flowProperties(&fields, f);
    const items = fields.slice();
    try testing.expectEqualStrings("Alias", items[4].label);
    try testing.expectEqualStrings("steamcontent.com", fields.value(items[4]));
    try testing.expect(items[4].dim);
}

test "a Flow's activity is its speeds now and its totals for the session" {
    var fields: Fields = .{};
    flowActivity(&fields, testFlow());
    try expectFields(&.{
        .{ .label = "Down rate", .value = "44.6 MB/s" },
        .{ .label = "Up rate", .value = "355.0 KB/s" },
        .{ .label = "Down session", .value = "116.3 MB" },
        .{ .label = "Up session", .value = "926.0 KB" },
    }, &fields);
}

test "an ICMP Flow's activity is messages, and it has no speed to report" {
    var fields: Fields = .{};
    flowActivity(&fields, .{
        .proto = .icmp,
        .family = .v4,
        .local_addr = @splat(0),
        .remote_addr = @splat(0),
        .local_port = 0,
        .remote_port = 0,
        .generation = 1,
        .msgs_sent = 4,
        .msgs_recv = 3,
    });
    try expectFields(&.{
        // No user-mode source reports ICMP message sizes, so there is no rate
        // to publish and none to show — the dash is the honest answer, not a
        // missing number.
        .{ .label = "Down rate", .value = format.idle, .dim = true },
        .{ .label = "Up rate", .value = format.idle, .dim = true },
        .{ .label = "Down session", .value = "3 msgs" },
        .{ .label = "Up session", .value = "4 msgs" },
    }, &fields);
}

test "a selected process reads out what it is, and what it has moved" {
    const row: snapshot.Row = .{
        .pid = 3412,
        .create_time = 1,
        .name = "C:\\Program Files (x86)\\Steam\\steam.exe",
        .recv = 212_500_000,
        .sent = 1_800_000,
        .recv_rate = 49_300_000,
        .sent_rate = 400_000,
    };
    var props: Fields = .{};
    processProperties(&props, row);
    try expectFields(&.{
        // Named by its exe, the way the table names it — the full path is its
        // own field below.
        .{ .label = "Name", .value = "steam.exe" },
        .{ .label = "PID", .value = "3412" },
        .{ .label = "Path", .value = "C:\\Program Files (x86)\\Steam\\steam.exe" },
        .{ .label = "Flows", .value = "0" },
    }, &props);

    var act: Fields = .{};
    processActivity(&act, row);
    try expectFields(&.{
        .{ .label = "Down rate", .value = "49.3 MB/s" },
        .{ .label = "Up rate", .value = "400.0 KB/s" },
        .{ .label = "Down session", .value = "212.5 MB" },
        .{ .label = "Up session", .value = "1.8 MB" },
    }, &act);
}

test "a service host names its services, and the Evicted-processes Row owns no PID" {
    // Service Attribution (CONTEXT.md): one service means the row *is* that
    // service; several mean a shared host, and naming them all beats picking
    // one.
    var one: Fields = .{};
    processProperties(&one, .{
        .pid = 2260,
        .name = "C:\\Windows\\System32\\svchost.exe",
        .services = &.{"Windows Update"},
    });
    try testing.expectEqualStrings("Service", one.slice()[2].label);
    try testing.expectEqualStrings("Windows Update", one.value(one.slice()[2]));

    var many: Fields = .{};
    processProperties(&many, .{
        .pid = 1608,
        .name = "C:\\Windows\\System32\\svchost.exe",
        .services = &.{ "Dhcp", "DNS Client" },
    });
    try testing.expectEqualStrings("Services", many.slice()[2].label);
    try testing.expectEqualStrings("Dhcp, DNS Client", many.value(many.slice()[2]));

    // CONTEXT.md "Evicted-processes Row": it owns no PID and no Flows — it is
    // where attribution stops, and a number in either field would be a lie.
    var evicted: Fields = .{};
    processProperties(&evicted, .{
        .pid = 0,
        .name = "(evicted processes)",
        .evicted_processes = true,
        .recv = 5000,
    });
    try expectFields(&.{
        .{ .label = "Name", .value = "(evicted processes)" },
        .{ .label = "PID", .value = format.idle, .dim = true },
    }, &evicted);
}

test "a Group Address is named, being what left the local endpoint" {
    // ADR-0004: a recognized Group Address is vacated from the local endpoint,
    // which no group could honestly occupy — so without naming it here, a
    // broadcast receive whose local and remote are both this machine is
    // inexplicable.
    var f = testFlow();
    f.group_kind = .multicast;
    var group: [16]u8 = @splat(0);
    group[0..4].* = .{ 239, 255, 255, 250 };
    f.group_addr = group;
    f.local_addr = @splat(0);
    f.local_port = 5353;

    var fields: Fields = .{};
    flowProperties(&fields, f);
    const items = fields.slice();
    try testing.expectEqualStrings("Group", items[2].label);
    try testing.expectEqualStrings("239.255.255.250 (multicast)", fields.value(items[2]));
}
