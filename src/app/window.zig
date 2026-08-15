//! The main window: an ordinary caller-owned HWND with its own D3D11 device
//! and swapchain, which dvui attaches to (dx11 attach mode, per
//! docs/research/gui-library-viability.md).
//!
//! Everything here is built to be done twice. Closing zPulsar's window destroys
//! the window, the swapchain, the device and the dvui context wholesale — that
//! teardown is what the Tray-idle RAM budget is made of (ADR-0002) — and a tray
//! click builds them all again through this same code. The one thing that is
//! *not* recreated is the window class: registering a class is per-process, and
//! dvui's backend takes the same position ("typically there's no reason to
//! unregister").
//!
//! There is one main window at a time by construction, so the wndproc's state
//! lives at module scope: a window procedure is a bare C callback with nowhere
//! to hang a context, and the alternative — stashing it in the window's own
//! extra bytes — is the slot dvui's backend already claims.

const std = @import("std");
const dvui = @import("dvui");

const Backend = dvui.backend;
const win32 = Backend.win32;

const class_name = win32.L("zPulsarMainWindow");
const title = win32.L("zPulsar");

/// Set by the wndproc when the close button is pressed, taken by the app loop.
var close_requested: bool = false;
/// Whether dvui currently owns this window's messages. False during creation
/// (before `Backend.attach`) and after teardown, when forwarding to the
/// backend would dereference window state that is gone.
var backend_attached: bool = false;
var class_registered: bool = false;

/// The window opens sized to a fraction of the screen, centred, and clamped so
/// it always fits: a monitor smaller than the design size is a laptop, not an
/// error.
const design_width = 1100;
const design_height = 760;

/// Create the main window, hidden. The caller creates the device, attaches
/// dvui, then shows it — showing an unattached window flashes an unpainted
/// frame.
pub fn create() error{ RegisterClassFailed, CreateWindowFailed }!win32.HWND {
    if (!class_registered) {
        const class: win32.WNDCLASSEXW = .{
            .cbSize = @sizeOf(win32.WNDCLASSEXW),
            .style = .{ .DBLCLKS = 1, .OWNDC = 1 },
            .lpfnWndProc = windowProc,
            .cbClsExtra = 0,
            // dvui keeps its per-window state in GWLP_USERDATA, but its
            // backend's own diagnostic tells you to reserve this, and its
            // example window does — match it rather than out-clever a pinned
            // dependency over one pointer's worth of window memory.
            .cbWndExtra = @sizeOf(usize),
            .hInstance = win32.GetModuleHandleW(null),
            .hIcon = null,
            .hCursor = win32.LoadCursorW(null, win32.IDC_ARROW),
            .hbrBackground = null,
            .lpszMenuName = null,
            .lpszClassName = class_name,
            .hIconSm = null,
        };
        if (0 == win32.RegisterClassExW(&class)) return error.RegisterClassFailed;
        class_registered = true;
    }

    const style = win32.WS_OVERLAPPEDWINDOW;
    const style_ex: win32.WINDOW_EX_STYLE = .{ .APPWINDOW = 1, .WINDOWEDGE = 1 };
    const hwnd = win32.CreateWindowExW(
        style_ex,
        class_name,
        title,
        style,
        win32.CW_USEDEFAULT,
        win32.CW_USEDEFAULT,
        0,
        0,
        null,
        null,
        win32.GetModuleHandleW(null),
        null,
    ) orelse return error.CreateWindowFailed;

    const dpi = win32.dpiFromHwnd(hwnd);
    const screen_w = win32.GetSystemMetricsForDpi(@intFromEnum(win32.SM_CXSCREEN), dpi);
    const screen_h = win32.GetSystemMetricsForDpi(@intFromEnum(win32.SM_CYSCREEN), dpi);
    var want: win32.RECT = .{
        .left = 0,
        .top = 0,
        .right = @min(screen_w, win32.scaleDpi(i32, design_width, dpi)),
        .bottom = @min(screen_h, win32.scaleDpi(i32, design_height, dpi)),
    };
    _ = win32.AdjustWindowRectEx(&want, style, 0, style_ex);
    const w = want.right - want.left;
    const h = want.bottom - want.top;
    _ = win32.SetWindowPos(
        hwnd,
        null,
        @divFloor(screen_w - w, 2),
        @divFloor(screen_h - h, 2),
        w,
        h,
        win32.SWP_NOCOPYBITS,
    );
    return hwnd;
}

/// Hand the window's messages to dvui (after `Backend.attach`), or take them
/// back (after teardown).
pub fn setAttached(attached: bool) void {
    backend_attached = attached;
}

/// Show and focus a freshly attached window — also the answer to a second
/// launch, which asks the running instance to put itself in front.
pub fn present(hwnd: win32.HWND) void {
    _ = win32.ShowWindow(hwnd, .{ .SHOWNORMAL = 1 });
    _ = win32.UpdateWindow(hwnd);
    _ = win32.SetForegroundWindow(hwnd);
}

/// Whether the close button was pressed since the last call. Close means
/// Tray-idle, not exit: exit lives in the tray menu.
pub fn takeCloseRequest() bool {
    defer close_requested = false;
    return close_requested;
}

fn windowProc(
    hwnd: win32.HWND,
    umsg: u32,
    wparam: win32.WPARAM,
    lparam: win32.LPARAM,
) callconv(.winapi) win32.LRESULT {
    var lp = lparam;
    switch (umsg) {
        // Close-to-tray. Handled here rather than forwarded, because the
        // backend's WM_CLOSE raises a dvui close event and the teardown has to
        // happen outside the frame that would be reading the context.
        win32.WM_CLOSE => {
            close_requested = true;
            return 0;
        },
        // dvui's dx11 backend expands a key message's repeat count into that
        // many events with `for (1..repeat_count)`, which panics on a zero.
        // Real keyboards always send at least 1; synthetic senders — remote
        // control, on-screen keyboards, automation — do not, and the UI
        // prototype found this the hard way. Normalize before the backend can
        // see it: a synthetic keystroke is worth one keystroke, not a crash.
        win32.WM_KEYDOWN, win32.WM_KEYUP, win32.WM_SYSKEYDOWN, win32.WM_SYSKEYUP => {
            const bits: usize = @bitCast(lparam);
            if (bits & 0xffff == 0) lp = @bitCast(bits | 1);
        },
        else => {},
    }
    if (backend_attached) return Backend.wndProc(hwnd, umsg, wparam, lp);
    return win32.DefWindowProcW(hwnd, umsg, wparam, lp);
}

/// Work around a dvui pre-1.0 leak that only a process which destroys devices
/// could ever notice.
///
/// dvui's dx11 backend creates its sampler states lazily, one per texture
/// interpolation, and `createSampler` also builds a blend state each time it
/// runs — overwriting the previous one *without releasing it*. It runs twice
/// per window (linear, then nearest), so every window strands exactly one
/// `ID3D11BlendState`. A stranded device child holds a reference to the
/// device, so the device is never destroyed: measured at ~100 orphaned driver
/// threads and ~27 MB per teardown-recreate cycle, none of it returned. An app
/// that creates one device and exits never sees this. zPulsar creates one per
/// Tray-idle cycle, which is the whole point of the cycle.
///
/// So supply one of the two samplers ourselves: dvui then finds it already
/// there, runs its creation path once instead of twice, and overwrites
/// nothing. What we put in the field is released by dvui's own teardown along
/// with everything else. On failure we simply leave the field alone — the leak
/// comes back, and rendering is unaffected either way.
pub fn preventBlendStateLeak(state: *Backend.WindowState) void {
    var desc = std.mem.zeroes(win32.D3D11_SAMPLER_DESC);
    // Exactly dvui's own nearest-interpolation sampler; a mismatch here would
    // change how nearest-filtered textures render.
    desc.Filter = win32.D3D11_FILTER.MIN_MAG_MIP_POINT;
    desc.AddressU = win32.D3D11_TEXTURE_ADDRESS_MODE.WRAP;
    desc.AddressV = win32.D3D11_TEXTURE_ADDRESS_MODE.WRAP;
    desc.AddressW = win32.D3D11_TEXTURE_ADDRESS_MODE.WRAP;

    var sampler: *win32.ID3D11SamplerState = undefined;
    if (state.device.CreateSamplerState(&desc, &sampler) != win32.S_OK) return;
    state.dx_options.sampler_nearest = sampler;
}

/// The D3D11 device, context and swapchain dvui renders through — ours to
/// create and, on teardown, dvui's to release (`WindowState.deinit`). Falls
/// back to the WARP software rasterizer, so a machine with no usable GPU still
/// gets a window rather than a fail-fast on startup.
pub fn createDevice(hwnd: win32.HWND) ?Backend.Directx11Options {
    const client = win32.getClientSize(hwnd);

    var desc = std.mem.zeroes(win32.DXGI_SWAP_CHAIN_DESC);
    desc.BufferCount = 2;
    desc.BufferDesc.Width = @intCast(client.cx);
    desc.BufferDesc.Height = @intCast(client.cy);
    desc.BufferDesc.Format = win32.DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferDesc.RefreshRate.Numerator = 60;
    desc.BufferDesc.RefreshRate.Denominator = 1;
    desc.Flags = @intFromEnum(win32.DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH);
    desc.BufferUsage = win32.DXGI_USAGE_RENDER_TARGET_OUTPUT;
    @setRuntimeSafety(false);
    desc.OutputWindow = hwnd;
    @setRuntimeSafety(true);
    desc.SampleDesc.Count = 1;
    desc.SampleDesc.Quality = 0;
    desc.Windowed = 1;
    desc.SwapEffect = win32.DXGI_SWAP_EFFECT_DISCARD;

    const flags: win32.D3D11_CREATE_DEVICE_FLAG = .{ .DEBUG = 0 };
    const levels = &[_]win32.D3D_FEATURE_LEVEL{
        win32.D3D_FEATURE_LEVEL_11_0,
        win32.D3D_FEATURE_LEVEL_10_0,
    };
    var level: win32.D3D_FEATURE_LEVEL = undefined;
    var device: *win32.ID3D11Device = undefined;
    var device_context: *win32.ID3D11DeviceContext = undefined;
    var swap_chain: *win32.IDXGISwapChain = undefined;

    var res = win32.D3D11CreateDeviceAndSwapChain(
        null,
        win32.D3D_DRIVER_TYPE_HARDWARE,
        null,
        flags,
        levels,
        levels.len,
        win32.D3D11_SDK_VERSION,
        &desc,
        &swap_chain,
        &device,
        &level,
        &device_context,
    );
    if (res == win32.DXGI_ERROR_UNSUPPORTED) {
        res = win32.D3D11CreateDeviceAndSwapChain(
            null,
            win32.D3D_DRIVER_TYPE_WARP,
            null,
            flags,
            levels,
            levels.len,
            win32.D3D11_SDK_VERSION,
            &desc,
            &swap_chain,
            &device,
            &level,
            &device_context,
        );
    }
    if (res != win32.S_OK) return null;

    return .{
        .device = device,
        .device_context = device_context,
        .swap_chain = swap_chain,
    };
}

/// Give back a device that never reached dvui. Only for the window that failed
/// to attach: once `Backend.attach` has it, releasing it is dvui's job and
/// doing it here as well would be a double release.
pub fn releaseDevice(device: Backend.Directx11Options) void {
    _ = device.swap_chain.IUnknown.Release();
    _ = device.device_context.IUnknown.Release();
    _ = device.device.IUnknown.Release();
}
