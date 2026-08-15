const std = @import("std");

// Module graph (ADR-0002): the Engine imports only std and the repo's win32
// facade; the app layer imports the Engine plus dvui. The boundary is
// structural — a module can only @import what is listed in its `imports`, so
// e.g. `@import("dvui")` or `@import("zigwin32")` inside the engine module is
// a compile error ("no module named ... available").
// Nuance: Zig analyzes lazily, so the error fires on any *referenced* import —
// an unused `const x = @import("dvui")` that nothing touches compiles
// silently, but any actual use cannot.
//
// Two win32 bindings end up in the process, deliberately. The app reaches
// Win32 through dvui's dx11 backend (`Backend.win32`) rather than the repo
// facade, because it has no choice: the D3D11 device it hands to
// `Backend.attach` has to be built from the same binding dvui's own types come
// from, and window, tray and device code cannot be split across two
// incompatible sets of HWND and COM types. So the facade stays what ADR-0002
// made it — the Engine's single door to the OS — and the app's window/tray/D3D
// surface goes through dvui's. The engine boundary, which is the one the ADR
// is about, is unaffected.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zigwin32 = b.dependency("zigwin32", .{});
    // dx11 in attach mode, and the three size levers the GUI research
    // measured the 1.92 MB floor with (docs/research/gui-library-viability.md).
    const dvui = b.dependency("dvui", .{
        .target = target,
        .optimize = optimize,
        .backend = .dx11,
        .freetype = false,
        .@"tree-sitter" = false,
        .@"tiny-file-dialogs" = false,
    });

    // win32 facade — the ONLY module that imports the zigwin32 binding.
    const win32_facade = b.createModule(.{
        .root_source_file = b.path("src/win32.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zigwin32", .module = zigwin32.module("win32") },
        },
    });

    // Engine — std + facade only. No UI, no binding, nothing else.
    const engine = b.addModule("engine", .{
        .root_source_file = b.path("src/engine/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "win32", .module = win32_facade },
        },
    });

    // App exe: tray + main window (issue #24).
    const app_mod = b.createModule(.{
        .root_source_file = b.path("src/app/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "engine", .module = engine },
            .{ .name = "dvui", .module = dvui.module("dvui_dx11") },
        },
    });
    const app_exe = b.addExecutable(.{
        .name = "zpulsar",
        .root_module = app_mod,
    });
    // No console: zPulsar is a tray app. It attaches to a parent console when
    // launched from one, so logs still land somewhere during development.
    app_exe.subsystem = .Windows;
    app_exe.win32_manifest = b.path("zpulsar.manifest");
    b.installArtifact(app_exe);

    const run_app = b.addRunArtifact(app_exe);
    run_app.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_app.addArgs(args);
    const run_app_step = b.step("run", "Run zPulsar (elevates: the manifest requires administrator)");
    run_app_step.dependOn(&run_app.step);

    // Debug-only headless target: proves the Engine boundary stays real and
    // doubles as the test/perf rig. Not part of release builds.
    if (optimize == .Debug) {
        const headless_mod = b.createModule(.{
            .root_source_file = b.path("src/headless/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "engine", .module = engine },
                .{ .name = "win32", .module = win32_facade },
            },
        });
        const headless_exe = b.addExecutable(.{
            .name = "zpulsar-headless",
            .root_module = headless_mod,
        });
        b.installArtifact(headless_exe);

        const run_headless = b.addRunArtifact(headless_exe);
        if (b.args) |args| run_headless.addArgs(args);
        const run_headless_step = b.step("run-headless", "Run the headless engine rig (requires elevation)");
        run_headless_step.dependOn(&run_headless.step);
    }

    const engine_tests = b.addTest(.{ .root_module = engine });
    const facade_tests = b.addTest(.{ .root_module = win32_facade });
    // The app's testable half is its view layer: formatting, Snapshot
    // aggregates, and the frozen row ordering — no window, no device.
    const app_tests = b.addTest(.{ .root_module = app_mod });
    const test_step = b.step("test", "Run engine, facade and app tests");
    test_step.dependOn(&b.addRunArtifact(engine_tests).step);
    test_step.dependOn(&b.addRunArtifact(facade_tests).step);
    test_step.dependOn(&b.addRunArtifact(app_tests).step);
}
