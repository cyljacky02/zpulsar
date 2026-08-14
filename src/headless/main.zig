//! Debug-only headless target (ADR-0002): the full hot path with no UI —
//! issue #20's tracer plus issue #21's Process Rows, issue #22's Flows,
//! issue #23's rates, issue #26's Hostname Attribution, issue #34's startup
//! resolver-cache snapshot, issue #25's Service Attribution, and issue #27's
//! ICMP. Brings the `zPulsarNet` session up, runs
//! the consumer, Engine, resolver and reverse-lookup threads, and renders a
//! live per-process table from acquired Snapshots — real image names, live
//! down/up speeds, In-session Totals, dimmed "(exited)" rows, the service a
//! row hosts (or the "(N services)" fallback with its list), each row's Flows
//! beneath it with Lingering ones dimmed, ICMP counted in messages, remote
//! names marked by the tier that produced them and each Flow's own service
//! inside a shared host, health flags. Requires elevation.
//!
//! Usage: zpulsar-headless [--duration <seconds>] [--dns-cache]
//! Default runs until Ctrl+C.

const std = @import("std");
const engine = @import("engine");
const win32 = @import("win32");

/// Runs on a dedicated thread while the default handler will terminate the
/// process right after we return FALSE, so the session is stopped
/// synchronously here — the main thread's deferred stop never runs on this
/// path. A concurrent or repeated stop is harmless (not-found is ignored).
fn consoleCtrlHandler(ctrl_type: u32) callconv(.winapi) win32.BOOL {
    _ = ctrl_type;
    const stopped = engine.etw_session.stopByName();
    std.debug.print("\nconsole-ctrl: session {s}\n", .{if (stopped) "stopped" else "already gone"});
    return win32.FALSE;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.page_allocator;
    const opts = try parseArgs(gpa, init.args);

    // The probe stands alone: no ETW session, no elevation, and nothing else
    // running to confuse what it printed.
    if (opts.dns_cache_only) return dumpDnsCache(gpa);

    if (win32.SetConsoleCtrlHandler(consoleCtrlHandler, win32.TRUE) == win32.FALSE)
        std.debug.print("warning: SetConsoleCtrlHandler failed; console-ctrl will leak the session\n", .{});

    const duration_s = opts.duration_s;

    const logical_cpus: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const session = engine.etw_session.start(logical_cpus) catch |err| {
        switch (err) {
            error.AccessDenied => std.debug.print(
                "error: access denied starting the {s} ETW session — run elevated\n",
                .{engine.etw_session.session_name},
            ),
            error.StartFailed => std.debug.print(
                "error: could not start the {s} ETW session (orphan cleanup or start failed)\n",
                .{engine.etw_session.session_name},
            ),
            error.EnableFailed => std.debug.print(
                "error: session started but enabling Kernel-Network failed; session stopped\n",
                .{},
            ),
        }
        std.process.exit(1);
    };
    if (session.adopted_orphan)
        std.debug.print("orphaned {s} session found: stopped by name, startup retried\n", .{engine.etw_session.session_name});

    // Fail-fast (ADR-0002): if the hot path cannot come up, stop the session
    // and exit — never a silently empty tracer.
    const eng = engine.runner.Engine.start(gpa, session) catch |err| {
        std.debug.print("error: engine start failed: {t}\n", .{err});
        session.stop();
        std.debug.print("{s} session stopped\n", .{engine.etw_session.session_name});
        std.process.exit(1);
    };
    // Full ordered shutdown: CloseTrace → ControlTrace(STOP) — never
    // skipped — → join both threads.
    defer {
        eng.stop();
        std.debug.print("{s} session stopped\n", .{engine.etw_session.session_name});
    }

    std.debug.print(
        "{s} up: consumer in ProcessTrace, Engine ticking every {d} ms, cold-start seeded\n",
        .{ engine.etw_session.session_name, engine.runner.flush_interval_ms },
    );
    if (duration_s > 0)
        std.debug.print("running for {d}s (Ctrl+C stops earlier)...\n", .{duration_s})
    else
        std.debug.print("running until Ctrl+C...\n", .{});
    win32.Sleep(1500); // leave the banner readable before the table takes over

    const vt = enableVtProcessing();
    const t0 = win32.GetTickCount64();
    var last_render_ms: u64 = 0;
    while (true) {
        // New-Snapshot wake, with a timeout so health/uptime stay fresh.
        _ = eng.snapshotWake().timedWait(500);
        const now_ms = win32.GetTickCount64() - t0;
        // Rendering is the rig's visibility surface: the throttle must stay
        // well inside the 200 ms attribution budget (delivery ≤ ~120 ms +
        // publish ≤ 50 ms leaves ~30 ms; trickle renders are immediate).
        if (now_ms - last_render_ms >= 100) {
            last_render_ms = now_ms;
            if (eng.acquireSnapshot()) |snap| {
                defer snap.release();
                render(snap, vt, now_ms);
            }
        }
        // Saturate: an absurd --duration must not overflow past the shutdown.
        if (duration_s > 0 and now_ms >= duration_s *| std.time.ms_per_s) break;
    }
}

/// The live table: one repaint built into a fixed buffer, one write. With VT
/// processing it repaints in place; without it, it scrolls.
fn render(snap: *engine.snapshot.Snapshot, vt: bool, uptime_ms: u64) void {
    var out_buf: [32 * 1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buf);
    writeTable(&w, snap, vt, uptime_ms) catch {}; // truncated repaint still prints
    std.debug.print("{s}", .{w.buffered()});
}

fn writeTable(
    w: *std.Io.Writer,
    snap: *engine.snapshot.Snapshot,
    vt: bool,
    uptime_ms: u64,
) !void {
    if (vt) try w.writeAll("\x1b[H\x1b[J");
    try w.print(
        "zPulsar headless — per-process In-session Totals  (snapshot #{d}, up {d}s)\n",
        .{ snap.seq, uptime_ms / 1000 },
    );
    try w.print("ring dropped: {d}   etw lost: {d}   svc lookups dropped: {d}", .{
        snap.health.ring_dropped,
        snap.health.etw_events_lost,
        snap.health.service_lookups_dropped,
    });
    if (snap.health.rebaselined)
        try w.writeAll("   [RE-BASELINED: loss occurred, totals may undercount]");
    try w.writeAll("\n\n");
    try w.print(
        "{s:>8}  {s:>4}  {s:>4}  {s:>4}  {s:>12}  {s:>12}  {s:>12}  {s:>12}  {s}\n",
        .{ "PID", "TCP", "UDP", "ICMP", "DOWN", "UP", "SENT", "RECV", "NAME" },
    );

    // Busiest first; the Snapshot itself stays untouched (it is immutable —
    // sort a copy; on allocation failure fall back to PID order).
    const heap = std.heap.page_allocator;
    const sorted: ?[]engine.snapshot.Row = heap.dupe(engine.snapshot.Row, snap.rows) catch null;
    defer if (sorted) |s| heap.free(s);
    const rows: []const engine.snapshot.Row = if (sorted) |s| blk: {
        std.mem.sort(engine.snapshot.Row, s, {}, rowBusierThan);
        break :blk s;
    } else snap.rows;
    const shown = @min(rows.len, max_rows);

    var total_sent: u64 = 0;
    var total_recv: u64 = 0;
    var down: u64 = 0;
    var up: u64 = 0;
    for (snap.rows) |r| {
        total_sent += r.sent;
        total_recv += r.recv;
        down += r.recv_rate;
        up += r.sent_rate;
    }

    var sent_buf: [16]u8 = undefined;
    var recv_buf: [16]u8 = undefined;
    var down_buf: [20]u8 = undefined;
    var up_buf: [20]u8 = undefined;
    var service_buf: [256]u8 = undefined;
    for (rows[0..shown]) |r| {
        if (r.exited and vt) try w.writeAll("\x1b[2m");
        try w.print("{d:>8}  {d:>4}  {d:>4}  {d:>4}  {s:>12}  {s:>12}  {s:>12}  {s:>12}  {s}{s}{s}{s}", .{
            r.pid,
            r.tcp_conns,
            r.udp_socks,
            r.icmp_flows,
            fmtRate(r.recv_rate, &down_buf),
            fmtRate(r.sent_rate, &up_buf),
            fmtBytes(r.sent, &sent_buf),
            fmtBytes(r.recv, &recv_buf),
            if (r.name.len > max_name_display) "…" else "",
            displayName(r.name),
            // The Evicted-processes Row says what it is in its own name.
            if (r.exited and !r.evicted_processes) " (exited)" else "",
            serviceLabel(r, &service_buf),
        });
        if (r.exited and vt) try w.writeAll("\x1b[22m");
        try w.writeAll("\n");
        const flows_shown = @min(r.flows.len, max_flows_per_row);
        for (r.flows[0..flows_shown]) |f| try writeFlow(w, f, r, vt);
        if (r.flows.len > flows_shown)
            try w.print("           … {d} more flows\n", .{r.flows.len - flows_shown});
    }
    if (snap.rows.len > shown)
        try w.print("  … {d} more processes\n", .{snap.rows.len - shown});
    try writeIcmpSection(w, snap, vt);
    // The spec's status bar: flow count, global speeds, session totals.
    try w.print("\n{d} processes   {d} flows   ↓ {s}  ↑ {s}   total sent {s}   recv {s}\n", .{
        snap.rows.len,
        snap.flows.len,
        fmtRate(down, &down_buf),
        fmtRate(up, &up_buf),
        fmtBytes(total_sent, &sent_buf),
        fmtBytes(total_recv, &recv_buf),
    });
}

/// ICMP gets its own section (issue #27). It contributes zero bytes by
/// design, so the byte-ordered table above buries a ping run under hundreds
/// of idle processes — which is correct for the table and useless for
/// watching ICMP work.
fn writeIcmpSection(w: *std.Io.Writer, snap: *engine.snapshot.Snapshot, vt: bool) !void {
    var shown: usize = 0;
    for (snap.rows) |r| {
        for (r.flows) |f| {
            if (f.proto != .icmp) continue;
            if (shown == 0) try w.writeAll("\nICMP — message counts, zero bytes by design\n");
            shown += 1;
            if (shown > max_icmp_rows) continue;
            var rbuf: [64]u8 = undefined;
            const dim = vt and f.lingering;
            if (dim) try w.writeAll("\x1b[2m");
            try w.print("{d:>8}  {s:>4}  {s:>18}  {d} sent / {d} recv{s}{s}\n", .{
                r.pid,
                @tagName(f.family),
                fmtEndpoint(f, .remote, &rbuf),
                f.msgs_sent,
                f.msgs_recv,
                if (f.lingering) "  [linger]" else "",
                if (r.exited) "  (exited)" else "",
            });
            if (dim) try w.writeAll("\x1b[22m");
        }
    }
    if (shown == 0) {
        try w.writeAll("\nICMP — none live\n");
    } else if (shown > max_icmp_rows) {
        try w.print("  … {d} more ICMP flows\n", .{shown - max_icmp_rows});
    }
}

const max_rows = 25;
const max_icmp_rows = 12;
/// Names longer than this are left-truncated — the tail (the exe name, the
/// registrable domain) is the interesting part, and wrapping lines would break
/// the in-place repaint.
const max_name_display = 56;
const max_hostname_display = 48;
const max_flows_per_row = 3;

/// One Flow line beneath its row; Lingering flows render dimmed (VT) and
/// tagged, matching the spec's dimmed Linger display. ICMP shows message
/// counts, never bytes — no user-mode source reports ICMP message sizes
/// (docs/research/icmp-visibility.md), so its speeds stay zero too.
fn writeFlow(
    w: *std.Io.Writer,
    f: engine.snapshot.Flow,
    row: engine.snapshot.Row,
    vt: bool,
) !void {
    var lbuf: [64]u8 = undefined;
    var rbuf: [64]u8 = undefined;
    var sbuf: [32]u8 = undefined;
    var rvbuf: [32]u8 = undefined;
    var dbuf: [20]u8 = undefined;
    var ubuf: [20]u8 = undefined;
    var svcbuf: [64]u8 = undefined;
    const line_dim = vt and f.lingering;
    if (line_dim) try w.writeAll("\x1b[2m");
    try w.print("           {s} gen{d}  {s} -> {s}  ↓ {s} ↑ {s}  {s} / {s}", .{
        @tagName(f.proto),
        f.generation,
        fmtEndpoint(f, .local, &lbuf),
        fmtEndpoint(f, .remote, &rbuf),
        fmtRate(f.recv_rate, &dbuf),
        fmtRate(f.sent_rate, &ubuf),
        fmtActivity(f, .sent, &sbuf),
        fmtActivity(f, .recv, &rvbuf),
    });
    try writeHostname(w, f, vt and !line_dim);
    try w.writeAll(flowServiceLabel(f, row, &svcbuf));
    if (f.lingering) try w.writeAll("  [linger]");
    if (line_dim) try w.writeAll("\x1b[22m");
    try w.writeAll("\n");
}

/// The remote name, marked by the tier that produced it (spec issue #18 UI;
/// docs/research/dns-client-etw.md §7): an observed name — the one the
/// process actually resolved — renders plain, while cache-snapshot and
/// reverse-lookup names are hints and render dimmed behind a badge. No name
/// means the bare endpoint above already says everything known.
fn writeHostname(w: *std.Io.Writer, f: engine.snapshot.Flow, dim_hints: bool) !void {
    const name = f.remote_hostname orelse return;
    const badge = switch (f.hostname_origin) {
        .observed => "",
        .cache => "[cache] ",
        .reverse => "[rDNS] ",
    };
    const dim = dim_hints and f.hostname_origin != .observed;
    if (dim) try w.writeAll("\x1b[2m");
    try w.print("  {s}{s}", .{ badge, truncateTail(name, max_hostname_display) });
    if (f.remote_alias) |alias|
        try w.print(" (via {s})", .{truncateTail(alias, max_hostname_display)});
    if (dim) try w.writeAll("\x1b[22m");
}

/// The Process Row's Service Attribution (spec issue #18, UI: "Process
/// (badge + name + Service Attribution + flow count)"). One hosted service
/// means the row *is* that service; several mean a shared host, and the
/// honest fallback names the count with the actual list — never a guess.
fn serviceLabel(r: engine.snapshot.Row, buf: []u8) []const u8 {
    if (r.services.len == 0) return "";
    if (r.services.len == 1)
        return std.fmt.bufPrint(buf, "  [{s}]", .{r.services[0]}) catch "";
    var w: std.Io.Writer = .fixed(buf);
    w.print("  ({d} services: ", .{r.services.len}) catch return "";
    for (r.services, 0..) |name, i| {
        if (i > 0) w.writeAll(", ") catch break;
        w.writeAll(name) catch break;
    }
    w.writeByte(')') catch {};
    return w.buffered();
}

/// A Flow's own service. Only shared hosts need it: a single-service row
/// already names its service once, on the row line. "?" is a Flow still
/// living under the row's fallback label — resolution pending, or failed.
fn flowServiceLabel(
    f: engine.snapshot.Flow,
    row: engine.snapshot.Row,
    buf: []u8,
) []const u8 {
    if (row.services.len < 2) return "";
    const name = f.service orelse return "  svc=?";
    return std.fmt.bufPrint(buf, "  svc={s}", .{name}) catch "";
}

/// Which half of a Flow to render — naming the side, rather than passing the
/// fields, keeps a caller from pairing one direction's bytes with the other's
/// address.
const Side = enum { local, remote };
const Direction = enum { sent, recv };

/// A Flow's activity in its own unit: bytes for TCP/UDP, "N msgs" for ICMP.
fn fmtActivity(f: engine.snapshot.Flow, dir: Direction, buf: []u8) []const u8 {
    if (f.proto == .icmp) {
        const msgs = switch (dir) {
            .sent => f.msgs_sent,
            .recv => f.msgs_recv,
        };
        return std.fmt.bufPrint(buf, "{d} msgs", .{msgs}) catch "?";
    }
    return fmtBytes(switch (dir) {
        .sent => f.sent,
        .recv => f.recv,
    }, buf);
}

/// "*" for an endpoint with nothing to show: a placeholder UDP socket's zero
/// remote, an ICMP Flow's absent local side, or its peer before the first
/// reply names it. ICMP has no ports, so its endpoints print bare addresses.
fn fmtEndpoint(f: engine.snapshot.Flow, side: Side, buf: []u8) []const u8 {
    const addr = switch (side) {
        .local => f.local_addr,
        .remote => f.remote_addr,
    };
    const port = switch (side) {
        .local => f.local_port,
        .remote => f.remote_port,
    };
    if (port == 0 and std.mem.allEqual(u8, &addr, 0)) return "*";
    return fmtAddr(f.family, addr, if (f.proto == .icmp) null else port, buf);
}

/// One address, with its port when the protocol has one (bracketed for v6).
/// v6 prints full-form groups — it's a debug rig.
fn fmtAddr(family: engine.event.Family, addr: [16]u8, port: ?u16, buf: []u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    switch (family) {
        .v4 => w.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] }) catch return "?",
        .v6 => {
            if (port != null) w.writeByte('[') catch return "?";
            var i: usize = 0;
            while (i < 16) : (i += 2) {
                if (i > 0) w.writeByte(':') catch return "?";
                w.print("{x}", .{std.mem.readInt(u16, addr[i..][0..2], .big)}) catch return "?";
            }
            if (port != null) w.writeByte(']') catch return "?";
        },
    }
    if (port) |p| w.print(":{d}", .{p}) catch return "?";
    return w.buffered();
}

/// Busiest first: current speed leads (that is what a live rig is for),
/// session totals break the ties among the idle.
fn rowBusierThan(_: void, a: engine.snapshot.Row, b: engine.snapshot.Row) bool {
    const rate_a = a.sent_rate + a.recv_rate;
    const rate_b = b.sent_rate + b.recv_rate;
    if (rate_a != rate_b) return rate_a > rate_b;
    return a.sent + a.recv > b.sent + b.recv;
}

/// The Snapshot's display path, bounded for one terminal line; "?" while the
/// process has no identity yet (traffic racing the rundown, or event loss).
fn displayName(name: []const u8) []const u8 {
    if (name.len == 0) return "?";
    return truncateTail(name, max_name_display);
}

/// Keep the tail, never cutting a multi-byte UTF-8 sequence in half.
fn truncateTail(text: []const u8, limit: usize) []const u8 {
    if (text.len <= limit) return text;
    var start = text.len - limit;
    while (start < text.len and text[start] & 0xC0 == 0x80) start += 1;
    return text[start..];
}

/// Decimal units per the spec's display rules (B/KB/MB/GB).
fn fmtBytes(v: u64, buf: []u8) []const u8 {
    const units = [_][]const u8{ "B", "KB", "MB", "GB", "TB" };
    var val: f64 = @floatFromInt(v);
    var unit: usize = 0;
    while (val >= 1000 and unit + 1 < units.len) : (unit += 1) val /= 1000;
    return if (unit == 0)
        std.fmt.bufPrint(buf, "{d} B", .{v}) catch "?"
    else
        std.fmt.bufPrint(buf, "{d:.1} {s}", .{ val, units[unit] }) catch "?";
}

/// A Snapshot's precomputed speed, in the same decimal units. Idle reads as
/// a dim dash rather than "0 B/s" — the spec's zero-value rule.
fn fmtRate(bytes_per_s: u64, buf: []u8) []const u8 {
    if (bytes_per_s == 0) return "—";
    var inner: [16]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}/s", .{fmtBytes(bytes_per_s, &inner)}) catch "?";
}

fn enableVtProcessing() bool {
    const handle = win32.GetStdHandle(win32.STD_ERROR_HANDLE);
    const mode = win32.getConsoleMode(handle) orelse return false;
    if (mode & win32.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) return true;
    return win32.setConsoleMode(handle, mode | win32.ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

const Options = struct {
    /// 0 runs until Ctrl+C.
    duration_s: u64 = 0,
    dns_cache_only: bool = false,
};

fn parseArgs(gpa: std.mem.Allocator, args: std.process.Args) !Options {
    var opts: Options = .{};
    var it = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer it.deinit();
    _ = it.skip(); // exe name
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--dns-cache")) {
            opts.dns_cache_only = true;
        } else if (std.mem.eql(u8, arg, "--duration")) {
            const value = it.next() orelse {
                std.debug.print("error: --duration needs a seconds argument\n", .{});
                std.process.exit(2);
            };
            opts.duration_s = std.fmt.parseInt(u64, value, 10) catch {
                std.debug.print("error: --duration: '{s}' is not a number of seconds\n", .{value});
                std.process.exit(2);
            };
        }
    }
    return opts;
}

/// `--dns-cache`: run the startup resolver-cache probe once and print what it
/// found. The dnsapi plumbing behind it (engine/dns_cache.zig) is the one path
/// in the Engine no unit test can reach — it needs the machine's real resolver
/// cache — so this is where it gets exercised, including the undocumented
/// `DnsGetCacheDataTable` layout and the freeing of what it hands back.
///
/// Note this mode leaves its own footprint: reading the cache re-reports every
/// entry through the DNS-Client provider as a 3008 in this process. In a full
/// run `core.applyDns` drops those; here nothing is listening.
fn dumpDnsCache(gpa: std.mem.Allocator) void {
    const snap = engine.dns_cache.query(gpa) orelse {
        // Exactly what the Engine does with this: nothing loud. Pre-start
        // names stay covered by the reverse-lookup lane, dimmed.
        std.debug.print(
            "resolver-cache probe failed — pre-start names fall back to the reverse-lookup lane\n",
            .{},
        );
        return;
    };
    defer snap.deinit(gpa);

    std.debug.print("resolver cache: {d} address records\n", .{snap.records.len});
    var buf: [64]u8 = undefined;
    for (snap.records) |r| {
        std.debug.print("  {s:>39}  {s}", .{ fmtAddr(r.ip.family, r.ip.addr, null, &buf), r.name });
        if (r.alias.len > 0) std.debug.print(" (via {s})", .{r.alias});
        std.debug.print("\n", .{});
    }
}
