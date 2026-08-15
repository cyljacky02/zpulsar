//! The tray icon and the window that owns it.
//!
//! This window is permanent: it is created before the main window and outlives
//! every teardown-recreate cycle, because the tray icon is zPulsar's whole
//! presence in Tray-idle. It is an ordinary invisible top-level window rather
//! than a message-only one, and that is deliberate — `TaskbarCreated`, the
//! broadcast that says Explorer restarted and every tray icon is gone, is only
//! delivered to top-level windows (ADR-0002).
//!
//! It is also the process's message-shaped front door: the tray menu, a second
//! launch asking the running instance to show itself, and the end of the
//! Windows session all arrive here.

const std = @import("std");
const dvui = @import("dvui");
const engine = @import("engine");

const Backend = dvui.backend;
const win32 = Backend.win32;

const log = std.log.scoped(.tray);

/// Also what a second launch looks for (single_instance.zig).
pub const class_name = win32.L("zPulsarTrayWindow");

const icon_id = 1;
const tray_callback = win32.WM_APP + 1;
const menu_show: usize = 1;
const menu_exit: usize = 2;

var nid: win32.NOTIFYICONDATAW = undefined;
var added = false;
var show_requested = false;
/// Explorer restarted; every tray icon in the system needs re-adding.
var taskbar_created_msg: u32 = 0;
/// "You are the running instance — show yourself." See `showMessage`.
var show_yourself_msg: u32 = 0;

/// The system-wide message id a second launch posts at us. Registered lazily
/// so both sides — the running instance and the one about to exit — resolve
/// the same id from the same string, whichever runs first.
pub fn showMessage() u32 {
    if (show_yourself_msg == 0)
        show_yourself_msg = win32.RegisterWindowMessageW(win32.L("zPulsarShowYourself"));
    return show_yourself_msg;
}

/// Bring the tray up: the permanent window, then its icon.
pub fn start() error{ RegisterClassFailed, CreateWindowFailed }!win32.HWND {
    const class: win32.WNDCLASSEXW = .{
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
    if (0 == win32.RegisterClassExW(&class)) return error.RegisterClassFailed;

    taskbar_created_msg = win32.RegisterWindowMessageW(win32.L("TaskbarCreated"));
    _ = showMessage();

    const hwnd = win32.CreateWindowExW(
        .{},
        class_name,
        win32.L("zPulsar"),
        .{}, // no WS_VISIBLE: this window is never shown, only messaged
        0,
        0,
        0,
        0,
        null,
        null,
        win32.GetModuleHandleW(null),
        null,
    ) orelse return error.CreateWindowFailed;

    nid = std.mem.zeroes(win32.NOTIFYICONDATAW);
    nid.cbSize = @sizeOf(win32.NOTIFYICONDATAW);
    nid.hWnd = hwnd;
    nid.uID = icon_id;
    nid.uFlags = .{ .MESSAGE = 1, .ICON = 1, .TIP = 1 };
    nid.uCallbackMessage = tray_callback;
    // zPulsar ships no icon resource yet, so it borrows the shell's generic
    // application icon rather than showing a blank square.
    nid.hIcon = win32.LoadIconW(null, win32.IDI_APPLICATION);
    writeTip("zPulsar — starting…");
    add();
    return hwnd;
}

/// Take the icon down. Skipping this leaves a ghost icon in the tray until the
/// user happens to hover over it, so it runs on every exit path.
pub fn stop() void {
    if (!added) return;
    _ = win32.Shell_NotifyIconW(win32.NIM_DELETE, &nid);
    added = false;
}

/// The tray's live text (view.totals.tooltip). This is the only thing zPulsar
/// says while the window is gone, so it keeps updating in Tray-idle.
pub fn setTooltip(text: []const u8) void {
    if (!added) return;
    writeTip(text);
    _ = win32.Shell_NotifyIconW(win32.NIM_MODIFY, &nid);
}

/// Whether something asked for the main window since the last call: a tray
/// click, the tray menu, or a second launch handing off.
pub fn takeShowRequest() bool {
    defer show_requested = false;
    return show_requested;
}

fn add() void {
    added = win32.Shell_NotifyIconW(win32.NIM_ADD, &nid) != 0;
    if (!added) log.warn("tray icon could not be added", .{});
}

fn writeTip(text: []const u8) void {
    // The caller bounds the text to fit (view.totals.tooltip_buf_len); a
    // conversion that somehow overran would still be terminated in range.
    var n = std.unicode.utf8ToUtf16Le(&nid.szTip, text) catch 0;
    if (n >= nid.szTip.len) n = nid.szTip.len - 1;
    nid.szTip[n] = 0;
}

fn trayWindowProc(
    hwnd: win32.HWND,
    umsg: u32,
    wparam: win32.WPARAM,
    lparam: win32.LPARAM,
) callconv(.winapi) win32.LRESULT {
    if (umsg == tray_callback) {
        // Default notify version: the mouse message is the low word of lparam.
        const mouse: u32 = @intCast(@as(usize, @bitCast(lparam)) & 0xFFFF);
        switch (mouse) {
            win32.WM_LBUTTONUP, win32.WM_LBUTTONDBLCLK => show_requested = true,
            win32.WM_RBUTTONUP => trackMenu(hwnd),
            else => {},
        }
        return 0;
    }
    // Explorer came back and took every tray icon with it when it went.
    if (umsg == taskbar_created_msg and taskbar_created_msg != 0) {
        added = false;
        add();
        return 0;
    }
    if (umsg == show_yourself_msg and show_yourself_msg != 0) {
        show_requested = true;
        return 0;
    }
    switch (umsg) {
        // Logging off or shutting down. Both halves matter: the session is
        // stopped here and now because the process can be killed the moment
        // this returns and ControlTrace(STOP) is never skipped (ADR-0002),
        // *and* the quit message still unwinds the app loop into the ordered
        // shutdown if Windows gives us the time. Stopping twice is harmless —
        // the second reports not-found and is ignored.
        win32.WM_ENDSESSION => {
            if (wparam != 0) {
                _ = engine.etw_session.stopByName();
                win32.PostQuitMessage(0);
            }
            return 0;
        },
        else => {},
    }
    return win32.DefWindowProcW(hwnd, umsg, wparam, lparam);
}

fn trackMenu(hwnd: win32.HWND) void {
    var pt: win32.POINT = undefined;
    _ = win32.GetCursorPos(&pt);
    const menu = win32.CreatePopupMenu() orelse return;
    defer _ = win32.DestroyMenu(menu);
    _ = win32.AppendMenuW(menu, win32.MF_STRING, menu_show, win32.L("Show zPulsar"));
    _ = win32.AppendMenuW(menu, win32.MF_SEPARATOR, 0, null);
    _ = win32.AppendMenuW(menu, win32.MF_STRING, menu_exit, win32.L("Exit"));
    // Foreground first, and a stray message after: without the pair, a tray
    // menu refuses to dismiss when you click away from it.
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
    _ = win32.PostMessageW(hwnd, win32.WM_NULL, 0, 0);
    switch (cmd) {
        menu_show => show_requested = true,
        // The only way to quit: closing the window means Tray-idle.
        menu_exit => win32.PostQuitMessage(0),
        else => {},
    }
}
