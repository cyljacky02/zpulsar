// PROTOTYPE — throwaway. Answers wayfinder ticket #10: what does zPulsar's main window look like?
// Fake data only; no monitoring code. Delete this whole directory once the v1 layout is locked.
const std = @import("std");
const dvui = @import("dvui");
const Backend = dvui.backend;
const win32 = Backend.win32;

const log = std.log.scoped(.zpulsar_proto);

var backend_attached = false;

pub fn main(init: std.process.Init) !void {
    dvui.Backend.Common.windowsAttachConsole() catch {};
    const gpa = init.gpa;
    dvui.io = init.io;

    const wnd = createWindow();
    const options = createDeviceD3D(wnd) orelse return error.CreateDeviceFailed;

    var window_state: Backend.WindowState = undefined;
    const backend = Backend.attach(wnd, &window_state, gpa, options, .{ .vsync = true }) catch |e| @panic(@errorName(e));
    defer backend.deinit();
    backend_attached = true;

    _ = win32.ShowWindow(wnd, .{ .SHOWNORMAL = 1 });
    _ = win32.UpdateWindow(wnd);

    const win: *dvui.Window = backend.getWindow();

    main_loop: while (true) switch (Backend.serviceMessageQueue()) {
        .queue_empty => {
            const nstime = win.beginWait(backend.hasEvent());
            try win.begin(nstime);

            dvui.label(@src(), "BASE: zPulsar UI prototype — scaffold OK", .{}, .{
                .font = .theme(.title),
                .color_fill = .{ .r = 0xff, .g = 0x60, .b = 0x60 },
                .background = true,
            });

            {
                var float = dvui.floatingWindow(@src(), .{}, .{ .min_size_content = .{ .w = 300, .h = 120 } });
                defer float.deinit();
                float.dragAreaSet(dvui.windowHeader("FLOAT: also OK?", "", null));
                dvui.label(@src(), "floating window content", .{}, .{});
            }

            for (dvui.events()) |*e| {
                if (e.evt == .window and e.evt.window.action == .close) break :main_loop;
                if (e.evt == .app and e.evt.app.action == .quit) break :main_loop;
            }

            _ = try win.end(.{});
        },
        .quit => break :main_loop,
    };
}

fn windowProc(
    hwnd: win32.HWND,
    umsg: u32,
    wparam: win32.WPARAM,
    lparam: win32.LPARAM,
) callconv(.winapi) win32.LRESULT {
    if (backend_attached)
        return Backend.wndProc(hwnd, umsg, wparam, lparam);
    return win32.DefWindowProcW(hwnd, umsg, wparam, lparam);
}

fn createWindow() win32.HWND {
    const class_name = win32.L("zPulsarProtoMain");
    {
        const opt: win32.WNDCLASSEXW = .{
            .cbSize = @sizeOf(win32.WNDCLASSEXW),
            .style = .{ .DBLCLKS = 1, .OWNDC = 1 },
            .lpfnWndProc = windowProc,
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
