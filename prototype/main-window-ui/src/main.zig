// PROTOTYPE — throwaway. Answers wayfinder ticket #10: what does zPulsar's main window look like?
// Fake data only; no monitoring code. Delete this whole directory once the v1 layout is locked.
//
// Three structurally different layouts, switchable with the floating bar or arrow keys:
//   A "Ledger"    — one dense sortable table, flows expand inline
//   B "Inspector" — master–detail: process list left, flow detail right
//   C "Pulse"     — dashboard: global meters, ranked activity bars
//
// Shared chrome under test (per the #9 architecture decision): a permanent hidden tray
// window owns the tray icon + live-speed tooltip; closing the main window destroys the
// window + D3D11 device + dvui context WHOLESALE (Tray-idle); tray click recreates them.
// The switcher bar shows "cycle N" — N grows each recreate, proving the full cycle works.
const std = @import("std");
const dvui = @import("dvui");
const Backend = dvui.backend;
const win32 = Backend.win32;

const data = @import("data.zig");
const state = @import("state.zig");
const common = @import("common.zig");
const va_ledger = @import("va_ledger.zig");
const vb_inspector = @import("vb_inspector.zig");
const vc_pulse = @import("vc_pulse.zig");
const switcher = @import("switcher.zig");

const log = std.log.scoped(.zpulsar_proto);

const WM_TRAY: u32 = win32.WM_APP + 1;
const TRAY_CMD_SHOW: usize = 1;
const TRAY_CMD_EXIT: usize = 2;

var backend_attached = false;
var main_hwnd: ?win32.HWND = null;
var want_show = false; // tray asked for the main window to be (re)created
var close_requested = false; // main window close button pressed
var main_class_registered = false;
var tray_nid: win32.NOTIFYICONDATAW = undefined;

pub fn main(init: std.process.Init) !void {
    dvui.Backend.Common.windowsAttachConsole() catch {};
    const gpa = init.gpa;
    dvui.io = init.io;

    data.init();

    // Permanent hidden window: owns the tray icon and outlives the main window.
    const tray_wnd = createTrayWindow();
    trayAdd(tray_wnd);
    defer trayRemove();

    var window_state: Backend.WindowState = undefined;
    var backend: ?Backend.Context = null;
    var win: *dvui.Window = undefined;

    var qpc_freq: win32.LARGE_INTEGER = .{ .QuadPart = 1 };
    _ = win32.QueryPerformanceFrequency(&qpc_freq);
    var qpc_last: win32.LARGE_INTEGER = .{ .QuadPart = 0 };
    _ = win32.QueryPerformanceCounter(&qpc_last);
    var sim_t: f64 = 0;
    var tray_accum: f64 = 1;
    var theme_pending = false;

    want_show = true; // open the main window on startup

    app_loop: while (true) {
        switch (Backend.serviceMessageQueue()) {
            .quit => break :app_loop,
            .queue_empty => {},
        }

        // fake data ticks in every state — monitoring continues during Tray-idle
        var qpc_now: win32.LARGE_INTEGER = .{ .QuadPart = 0 };
        _ = win32.QueryPerformanceCounter(&qpc_now);
        const dt = @min(0.1, @as(f64, @floatFromInt(qpc_now.QuadPart - qpc_last.QuadPart)) / @as(f64, @floatFromInt(qpc_freq.QuadPart)));
        qpc_last = qpc_now;
        sim_t += dt;
        data.tick(dt, sim_t);

        tray_accum += dt;
        if (tray_accum >= 0.5) {
            tray_accum = 0;
            trayUpdateTooltip();
        }

        // Teardown: destroy window + D3D device + dvui context wholesale.
        if (close_requested) {
            close_requested = false;
            if (backend) |b| {
                b.deinit(); // DestroyWindow -> WM_DESTROY -> WindowState.deinit releases everything
                backend_attached = false;
                backend = null;
                main_hwnd = null;
                log.info("main window torn down — tray-idle (cycle {d} done)", .{state.cycle});
            }
        }

        // Recreate on tray click (or first open).
        if (backend == null and want_show) {
            want_show = false;
            const wnd = createMainWindow();
            const options = createDeviceD3D(wnd) orelse return error.CreateDeviceFailed;
            backend = Backend.attach(wnd, &window_state, gpa, options, .{ .vsync = true }) catch |e| @panic(@errorName(e));
            main_hwnd = wnd;
            backend_attached = true;
            win = backend.?.getWindow();
            theme_pending = true;
            state.cycle += 1;
            _ = win32.ShowWindow(wnd, .{ .SHOWNORMAL = 1 });
            _ = win32.UpdateWindow(wnd);
            _ = win32.SetForegroundWindow(wnd);
            log.info("main window created (cycle {d})", .{state.cycle});
        }

        // Tray-idle: no window, no rendering; keep servicing messages cheaply.
        if (backend == null) {
            win32.Sleep(30);
            continue :app_loop;
        }

        const b = backend.?;
        const nstime = win.beginWait(b.hasEvent());
        try win.begin(nstime);

        if (theme_pending) {
            theme_pending = false;
            dvui.themeSet(dvui.Theme.builtin.adwaita_dark);
        }

        switch (state.variant) {
            .a_ledger => va_ledger.frame(),
            .b_inspector => vb_inspector.frame(),
            .c_pulse => vc_pulse.frame(),
        }
        switcher.frame();

        for (dvui.events()) |*e| {
            if (e.evt == .app and e.evt.app.action == .quit) break :app_loop;
        }

        _ = try win.end(.{});
    }

    if (backend) |b| {
        b.deinit();
        backend_attached = false;
    }
}

// ---------- main window ----------

fn mainWindowProc(
    hwnd: win32.HWND,
    umsg: u32,
    wparam: win32.WPARAM,
    lparam: win32.LPARAM,
) callconv(.winapi) win32.LRESULT {
    switch (umsg) {
        // Close-to-tray: request wholesale teardown; exit lives in the tray menu.
        win32.WM_CLOSE => {
            close_requested = true;
            return 0;
        },
        else => {},
    }
    if (backend_attached)
        return Backend.wndProc(hwnd, umsg, wparam, lparam);
    return win32.DefWindowProcW(hwnd, umsg, wparam, lparam);
}

fn createMainWindow() win32.HWND {
    const class_name = win32.L("zPulsarProtoMain");
    if (!main_class_registered) {
        const opt: win32.WNDCLASSEXW = .{
            .cbSize = @sizeOf(win32.WNDCLASSEXW),
            .style = .{ .DBLCLKS = 1, .OWNDC = 1 },
            .lpfnWndProc = mainWindowProc,
            .cbClsExtra = 0,
            .cbWndExtra = @sizeOf(usize),
            .hInstance = win32.GetModuleHandleW(null),
            .hIcon = null,
            .hCursor = win32.LoadCursorW(null, win32.IDC_ARROW),
            .hbrBackground = null,
            .lpszMenuName = null,
            .lpszClassName = class_name,
            .hIconSm = null,
        };
        if (0 == win32.RegisterClassExW(&opt)) win32.panicWin32("RegisterClass", win32.GetLastError());
        main_class_registered = true;
    }
    const style = win32.WS_OVERLAPPEDWINDOW;
    const style_ex: win32.WINDOW_EX_STYLE = .{ .APPWINDOW = 1, .WINDOWEDGE = 1 };
    const wnd = win32.CreateWindowExW(
        style_ex,
        class_name,
        win32.L("zPulsar — UI prototype (fake data)"),
        style,
        win32.CW_USEDEFAULT,
        win32.CW_USEDEFAULT,
        0,
        0,
        null,
        null,
        win32.GetModuleHandleW(null),
        null,
    ) orelse win32.panicWin32("CreateWindow", win32.GetLastError());

    const dpi = win32.dpiFromHwnd(wnd);
    const screen_width = win32.GetSystemMetricsForDpi(@intFromEnum(win32.SM_CXSCREEN), dpi);
    const screen_height = win32.GetSystemMetricsForDpi(@intFromEnum(win32.SM_CYSCREEN), dpi);
    var wnd_size: win32.RECT = .{
        .left = 0,
        .top = 0,
        .right = @min(screen_width, win32.scaleDpi(i32, 1100, dpi)),
        .bottom = @min(screen_height, win32.scaleDpi(i32, 760, dpi)),
    };
    _ = win32.AdjustWindowRectEx(&wnd_size, style, 0, style_ex);
    const wnd_width = wnd_size.right - wnd_size.left;
    const wnd_height = wnd_size.bottom - wnd_size.top;
    _ = win32.SetWindowPos(
        wnd,
        null,
        @divFloor(screen_width - wnd_width, 2),
        @divFloor(screen_height - wnd_height, 2),
        wnd_width,
        wnd_height,
        win32.SWP_NOCOPYBITS,
    );
    return wnd;
}

// ---------- tray window (permanent) ----------

fn trayWindowProc(
    hwnd: win32.HWND,
    umsg: u32,
    wparam: win32.WPARAM,
    lparam: win32.LPARAM,
) callconv(.winapi) win32.LRESULT {
    if (umsg == WM_TRAY) {
        const ev: u32 = @intCast(@as(usize, @bitCast(lparam)) & 0xFFFF);
        switch (ev) {
            win32.WM_LBUTTONUP, win32.WM_LBUTTONDBLCLK => want_show = true,
            win32.WM_RBUTTONUP => trayMenu(hwnd),
            else => {},
        }
        return 0;
    }
    return win32.DefWindowProcW(hwnd, umsg, wparam, lparam);
}

fn createTrayWindow() win32.HWND {
    const class_name = win32.L("zPulsarProtoTray");
    const opt: win32.WNDCLASSEXW = .{
        .cbSize = @sizeOf(win32.WNDCLASSEXW),
        .style = .{},
        .lpfnWndProc = trayWindowProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = win32.GetModuleHandleW(null),
        .hIcon = null,
        .hCursor = null,
        .hbrBackground = null,
        .lpszMenuName = null,
        .lpszClassName = class_name,
        .hIconSm = null,
    };
    if (0 == win32.RegisterClassExW(&opt)) win32.panicWin32("RegisterClass tray", win32.GetLastError());
    return win32.CreateWindowExW(
        .{},
        class_name,
        win32.L("zPulsar tray"),
        .{}, // no style: never shown
        0,
        0,
        0,
        0,
        null,
        null,
        win32.GetModuleHandleW(null),
        null,
    ) orelse win32.panicWin32("CreateWindow tray", win32.GetLastError());
}

fn trayMenu(hwnd: win32.HWND) void {
    var pt: win32.POINT = undefined;
    _ = win32.GetCursorPos(&pt);
    const menu = win32.CreatePopupMenu() orelse return;
    defer _ = win32.DestroyMenu(menu);
    _ = win32.AppendMenuW(menu, win32.MF_STRING, TRAY_CMD_SHOW, win32.L("Show zPulsar"));
    _ = win32.AppendMenuW(menu, win32.MF_SEPARATOR, 0, null);
    _ = win32.AppendMenuW(menu, win32.MF_STRING, TRAY_CMD_EXIT, win32.L("Exit"));
    _ = win32.SetForegroundWindow(hwnd);
    const cmd: usize = @intCast(win32.TrackPopupMenu(
        menu,
        .{ .RETURNCMD = 1, .NONOTIFY = 1 },
        pt.x,
        pt.y,
        0,
        hwnd,
        null,
    ));
    switch (cmd) {
        TRAY_CMD_SHOW => want_show = true,
        TRAY_CMD_EXIT => win32.PostQuitMessage(0),
        else => {},
    }
}

fn trayAdd(hwnd: win32.HWND) void {
    tray_nid = std.mem.zeroes(win32.NOTIFYICONDATAW);
    tray_nid.cbSize = @sizeOf(win32.NOTIFYICONDATAW);
    tray_nid.hWnd = hwnd;
    tray_nid.uID = 1;
    tray_nid.uFlags = .{ .MESSAGE = 1, .ICON = 1, .TIP = 1 };
    tray_nid.uCallbackMessage = WM_TRAY;
    tray_nid.hIcon = win32.LoadIconW(null, win32.IDI_APPLICATION);
    traySetTip("zPulsar (prototype) — starting…");
    if (win32.Shell_NotifyIconW(win32.NIM_ADD, &tray_nid) == 0) {
        log.warn("tray icon add failed", .{});
    }
}

fn trayRemove() void {
    _ = win32.Shell_NotifyIconW(win32.NIM_DELETE, &tray_nid);
}

fn traySetTip(utf8: []const u8) void {
    var n = std.unicode.utf8ToUtf16Le(&tray_nid.szTip, utf8) catch 0;
    if (n >= tray_nid.szTip.len) n = tray_nid.szTip.len - 1;
    tray_nid.szTip[n] = 0;
}

fn trayUpdateTooltip() void {
    var b1: [48]u8 = undefined;
    var b2: [48]u8 = undefined;
    var line: [120]u8 = undefined;
    const txt = std.fmt.bufPrint(&line, "zPulsar — ↓ {s}   ↑ {s}", .{
        common.fmtSpeed(&b1, data.global_down_bps),
        common.fmtSpeed(&b2, data.global_up_bps),
    }) catch return;
    traySetTip(txt);
    _ = win32.Shell_NotifyIconW(win32.NIM_MODIFY, &tray_nid);
}

// ---------- D3D11 ----------

fn createDeviceD3D(hwnd: win32.HWND) ?Backend.Directx11Options {
    const client_size = win32.getClientSize(hwnd);

    var sd = std.mem.zeroes(win32.DXGI_SWAP_CHAIN_DESC);
    sd.BufferCount = 2;
    sd.BufferDesc.Width = @intCast(client_size.cx);
    sd.BufferDesc.Height = @intCast(client_size.cy);
    sd.BufferDesc.Format = win32.DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = @intFromEnum(win32.DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH);
    sd.BufferUsage = win32.DXGI_USAGE_RENDER_TARGET_OUTPUT;
    @setRuntimeSafety(false);
    sd.OutputWindow = hwnd;
    @setRuntimeSafety(true);
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = 1;
    sd.SwapEffect = win32.DXGI_SWAP_EFFECT_DISCARD;

    const createDeviceFlags: win32.D3D11_CREATE_DEVICE_FLAG = .{ .DEBUG = 0 };
    var featureLevel: win32.D3D_FEATURE_LEVEL = undefined;
    const featureLevelArray = &[_]win32.D3D_FEATURE_LEVEL{ win32.D3D_FEATURE_LEVEL_11_0, win32.D3D_FEATURE_LEVEL_10_0 };

    var device: *win32.ID3D11Device = undefined;
    var device_context: *win32.ID3D11DeviceContext = undefined;
    var swap_chain: *win32.IDXGISwapChain = undefined;

    var res: win32.HRESULT = win32.D3D11CreateDeviceAndSwapChain(
        null,
        win32.D3D_DRIVER_TYPE_HARDWARE,
        null,
        createDeviceFlags,
        featureLevelArray,
        2,
        win32.D3D11_SDK_VERSION,
        &sd,
        &swap_chain,
        &device,
        &featureLevel,
        &device_context,
    );
    if (res == win32.DXGI_ERROR_UNSUPPORTED) {
        res = win32.D3D11CreateDeviceAndSwapChain(
            null,
            win32.D3D_DRIVER_TYPE_WARP,
            null,
            createDeviceFlags,
            featureLevelArray,
            2,
            win32.D3D11_SDK_VERSION,
            &sd,
            &swap_chain,
            &device,
            &featureLevel,
            &device_context,
        );
    }
    if (res != win32.S_OK) return null;

    return Backend.Directx11Options{
        .device = device,
        .device_context = device_context,
        .swap_chain = swap_chain,
    };
}
