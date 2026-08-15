//! zPulsar: the tray app around the Engine (issue #24).
//!
//! One process, two states. **Window-open** is the full thing: a caller-owned
//! HWND with a D3D11 device and a dvui context attached to it, rendering the
//! Ledger from Snapshots at the latency budget. **Tray-idle** is the window,
//! swapchain, device and dvui context *destroyed* — not hidden — with
//! monitoring running underneath at a slower posture and the tray tooltip as
//! the only surface (ADR-0002). Closing goes one way, clicking the tray goes
//! the other, and the recreate takes the same code path as the first open, so
//! the cycle cannot rot into a special case.
//!
//! Startup is fail-fast: elevated by manifest, and if the Engine cannot come
//! up the user gets a message box and no process, never a window that shows
//! nothing. Shutdown stops the `zPulsarNet` ETW session on every path out —
//! sessions outlive their process, so the tray menu, a console Ctrl+C and the
//! end of the Windows session each have to be one of those paths.

const std = @import("std");
const dvui = @import("dvui");
const engine = @import("engine");

const ledger_mod = @import("ledger.zig");
const single_instance = @import("single_instance.zig");
const tray = @import("tray.zig");
const view = @import("view.zig");
const window = @import("window.zig");

const Backend = dvui.backend;
const win32 = Backend.win32;

const log = std.log.scoped(.zpulsar);

/// The tray tooltip's beat — the spec's 1 s, and the reason the Tray-idle loop
/// wakes at all.
const tooltip_interval_ms: u64 = 1_000;
/// How long the Tray-idle loop blocks on the message queue between tooltip
/// updates. Short enough that a tray click feels instant, long enough that
/// doing nothing costs nothing.
const idle_wait_ms: u32 = 200;

test {
    _ = @import("view.zig");
}

pub fn main(init: std.process.Init) !void {
    // The startup failure messages below are UTF-16 literals built at comptime
    // and are longer than the default quota allows.
    @setEvalBranchQuota(10_000);
    // A tray app has no console of its own; borrow the one it was launched
    // from so std.log has somewhere to go during development.
    dvui.Backend.Common.windowsAttachConsole() catch {};
    dvui.io = init.io;
    const gpa = init.gpa;

    if (single_instance.claim() == .already_running) {
        // The running instance shows itself and we leave. Only if nothing
        // answers do we say anything: an app that exits in silence looks
        // broken to whoever just double-clicked it.
        if (!single_instance.handOff())
            alert(win32.L("zPulsar is already running on this machine."));
        return;
    }

    // Ctrl+C in an attached console kills us without unwinding, so the session
    // is stopped from the handler itself.
    if (win32.SetConsoleCtrlHandler(consoleCtrlHandler, 1) == 0)
        log.warn("console-ctrl handler not installed; Ctrl+C would leak the ETW session", .{});

    const logical_cpus: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const session = engine.etw_session.start(logical_cpus) catch |err| {
        alert(switch (err) {
            error.AccessDenied => win32.L(
                "zPulsar needs administrator rights to capture network events.\n\n" ++
                    "Start it elevated and try again.",
            ),
            error.StartFailed => win32.L(
                "zPulsar could not start its ETW capture session.\n\n" ++
                    "Another copy may be holding it, or the session could not be created.",
            ),
            error.EnableFailed => win32.L(
                "zPulsar started its capture session but could not enable the " ++
                    "event providers it needs. The session has been stopped.",
            ),
        });
        std.process.exit(1);
    };
    if (session.adopted_orphan)
        log.info("orphaned {s} session found and stopped; startup retried", .{engine.etw_session.session_name});

    const eng = engine.runner.Engine.start(gpa, session) catch |err| {
        log.err("engine start failed: {t}", .{err});
        // ControlTrace(STOP) is never skipped, including on the way out of a
        // failed startup.
        session.stop();
        alert(win32.L(
            "zPulsar could not start monitoring.\n\n" ++
                "Its capture session has been stopped and nothing is left running.",
        ));
        std.process.exit(1);
    };
    // Full ordered shutdown: CloseTrace, ControlTrace(STOP), then the threads.
    defer eng.stop();

    // The tray comes up only once monitoring is real: an icon for an app that
    // is about to fail its own startup is worse than no icon.
    _ = tray.start() catch |err| {
        log.err("tray window failed: {t}", .{err});
        // `std.process.exit` does not unwind, so the `defer` above never runs
        // here — and a skipped ControlTrace(STOP) leaves `zPulsarNet` behind
        // for the next launch to adopt. Shut down properly first, then leave.
        eng.stop();
        alert(win32.L("zPulsar could not create its tray icon."));
        std.process.exit(1);
    };
    defer tray.stop();

    var ledger: ledger_mod.Ledger = .{};
    defer ledger.deinit(gpa);

    var window_state: Backend.WindowState = undefined;
    var backend: ?Backend.Context = null;
    var main_hwnd: ?win32.HWND = null;
    var theme_pending = false;
    var cycles: u32 = 0;

    // The window opens on launch; every later open comes from the tray.
    var want_show = true;
    const t0 = win32.GetTickCount64();
    var last_tooltip: u64 = 0;

    app: while (true) {
        switch (Backend.serviceMessageQueue()) {
            .quit => break :app,
            .queue_empty => {},
        }
        if (tray.takeShowRequest()) want_show = true;
        const now = win32.GetTickCount64() - t0;

        // Teardown, into Tray-idle. Wholesale: the backend's deinit destroys
        // the window, which releases the swapchain, the device and the dvui
        // context with it — the tray-idle RAM budget is made of exactly this.
        if (window.takeCloseRequest()) {
            if (backend) |b| {
                b.deinit();
                window.setAttached(false);
                backend = null;
                main_hwnd = null;
                eng.setPosture(.tray_idle);
                log.info("Tray-idle: window, device and dvui context destroyed (cycle {d})", .{cycles});
            }
        }

        if (want_show) {
            want_show = false;
            if (main_hwnd) |hwnd| {
                // Already open — a tray click or a second launch just wants it
                // in front.
                window.present(hwnd);
            } else if (openWindow(gpa, &window_state)) |opened| {
                backend = opened.backend;
                main_hwnd = opened.hwnd;
                theme_pending = true;
                cycles += 1;
                eng.setPosture(.window_open);
                window.present(opened.hwnd);
                log.info("main window open (cycle {d})", .{cycles});
            } else |err| {
                // Monitoring is unaffected, so this is not fatal: say so once
                // and stay in Tray-idle rather than taking the Engine down
                // with the window.
                log.err("main window could not be created: {t}", .{err});
                alert(win32.L(
                    "zPulsar could not open its window. Monitoring continues in " ++
                        "the tray; click the tray icon to try again.",
                ));
            }
        }

        // The tooltip is the only thing zPulsar says in Tray-idle, so it keeps
        // its beat in both postures.
        if (now - last_tooltip >= tooltip_interval_ms) {
            last_tooltip = now;
            if (eng.acquireSnapshot()) |snap| {
                defer snap.release();
                var buf: [view.totals.tooltip_buf_len]u8 = undefined;
                tray.setTooltip(view.totals.tooltip(&buf, view.totals.of(snap)));
            }
        }

        const b = backend orelse {
            // Tray-idle: nothing to draw. Block on the message queue instead
            // of spinning — this is where the idle CPU budget is won.
            _ = win32.MsgWaitForMultipleObjects(0, null, 0, idle_wait_ms, win32.QS_ALLINPUT);
            continue :app;
        };

        const win = b.getWindow();
        const nstime = win.beginWait(b.hasEvent());
        try win.begin(nstime);
        if (theme_pending) {
            // Every recreate builds a fresh dvui context, so the theme is set
            // per cycle, not once per process.
            theme_pending = false;
            dvui.themeSet(dvui.Theme.builtin.adwaita_dark);
        }

        if (eng.acquireSnapshot()) |snap| {
            defer snap.release();
            ledger.frame(gpa, snap, now);
        } else {
            // Before the first Snapshot lands. An empty table would read as
            // "nothing is happening on this machine", which is a lie.
            dvui.label(@src(), "starting…", .{}, .{ .gravity_x = 0.5, .gravity_y = 0.5 });
        }

        // dvui's own quit event — a safety net rather than a route we use, so
        // the frame is still closed properly before leaving.
        var quit = false;
        for (dvui.events()) |*e| {
            if (e.evt == .app and e.evt.app.action == .quit) quit = true;
        }
        _ = try win.end(.{});
        if (quit) break :app;
    }

    // Leaving by the tray menu or the end of the Windows session: tear the
    // window down explicitly, then the defers take the icon and the session.
    if (backend) |b| {
        b.deinit();
        window.setAttached(false);
    }
}

const OpenedWindow = struct {
    hwnd: win32.HWND,
    backend: Backend.Context,
};

/// The first open and every recreate, one path. The window is created hidden
/// and only shown once dvui owns it, so a cycle never flashes an unpainted
/// frame.
fn openWindow(
    gpa: std.mem.Allocator,
    window_state: *Backend.WindowState,
) !OpenedWindow {
    const hwnd = try window.create();
    errdefer _ = win32.DestroyWindow(hwnd);

    const device = window.createDevice(hwnd) orelse return error.CreateDeviceFailed;
    // Ours until `attach` takes it; after that dvui's teardown owns it. A
    // failed attach in a process that keeps running would otherwise strand a
    // whole device, which is the very thing this cycle exists to avoid.
    errdefer window.releaseDevice(device);

    const backend = try Backend.attach(hwnd, window_state, gpa, device, .{ .vsync = true });
    window.preventBlendStateLeak(window_state);
    window.setAttached(true);
    return .{ .hwnd = hwnd, .backend = backend };
}

/// Ctrl+C in an attached console. This runs on a handler thread while the
/// default handler is waiting to terminate the process the moment we return
/// FALSE — there is no ordered shutdown to be had here, and reaching for one
/// would mean joining the Engine's threads from underneath a main thread that
/// is still mid-frame. So this path keeps the invariant that actually matters
/// (ADR-0002: ETW sessions outlive their process, so ControlTrace(STOP) is
/// never skipped) and lets the OS reclaim the rest. The headless rig's handler
/// is the same shape for the same reason.
fn consoleCtrlHandler(ctrl_type: u32) callconv(.winapi) win32.BOOL {
    _ = ctrl_type;
    _ = engine.etw_session.stopByName();
    return 0;
}

fn alert(text: [*:0]const u16) void {
    _ = win32.MessageBoxW(null, text, win32.L("zPulsar"), .{
        .ICONHAND = 1,
        .SETFOREGROUND = 1,
    });
}
