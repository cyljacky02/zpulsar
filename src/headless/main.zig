//! Debug-only headless target (ADR-0002): runs the Engine without any UI,
//! proving the module boundary and doubling as the test/perf rig. For this
//! walking skeleton it brings the `zPulsarNet` session up, enables
//! Kernel-Network, prints the cold-start TCP/UDP table row counts, and stops
//! the session on every exit path. Requires elevation.
//!
//! Usage: zpulsar-headless [--hold <seconds>]
//! `--hold` keeps the session up (e.g. to exercise the console-ctrl path);
//! default is to exit immediately after the snapshot.

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
    std.debug.print("console-ctrl: session {s}\n", .{if (stopped) "stopped" else "already gone"});
    return win32.FALSE;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.page_allocator;

    if (win32.SetConsoleCtrlHandler(consoleCtrlHandler, win32.TRUE) == win32.FALSE)
        std.debug.print("warning: SetConsoleCtrlHandler failed; console-ctrl will leak the session\n", .{});

    const hold_seconds = try parseHoldArg(gpa, init.args);

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
    defer {
        session.stop();
        std.debug.print("{s} session stopped\n", .{engine.etw_session.session_name});
    }

    if (session.adopted_orphan)
        std.debug.print("orphaned {s} session found: stopped by name, startup retried\n", .{engine.etw_session.session_name});
    std.debug.print(
        "{s} session started: QPC clock, real-time, 16 KB buffers, {d}/{d} min/max buffers, 1 s FlushTimer\n",
        .{ engine.etw_session.session_name, 2 * logical_cpus, 4 * logical_cpus },
    );
    std.debug.print("Kernel-Network enabled (keywords IPv4|IPv6)\n", .{});

    const counts = engine.tables.snapshotCounts(gpa) catch {
        std.debug.print("error: TCP/UDP table snapshot failed\n", .{});
        // The deferred stop still runs; exit through the error path.
        return error.SnapshotFailed;
    };
    std.debug.print(
        "cold-start table rows: TCPv4={d} TCPv6={d} UDPv4={d} UDPv6={d}\n",
        .{ counts.tcp4, counts.tcp6, counts.udp4, counts.udp6 },
    );

    if (hold_seconds > 0) {
        std.debug.print("holding session for {d}s (Ctrl+C stops it early)...\n", .{hold_seconds});
        win32.Sleep(@intCast(hold_seconds * std.time.ms_per_s));
    }
}

fn parseHoldArg(gpa: std.mem.Allocator, args: std.process.Args) !u64 {
    var it = try std.process.Args.Iterator.initAllocator(args, gpa);
    defer it.deinit();
    _ = it.skip(); // exe name
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--hold")) {
            const value = it.next() orelse {
                std.debug.print("error: --hold needs a seconds argument\n", .{});
                std.process.exit(2);
            };
            return std.fmt.parseInt(u64, value, 10) catch {
                std.debug.print("error: --hold: '{s}' is not a number of seconds\n", .{value});
                std.process.exit(2);
            };
        }
    }
    return 0;
}
