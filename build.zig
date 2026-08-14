const std = @import("std");

// Module graph (ADR-0002): the Engine imports only std and the repo's win32
// facade; only the facade imports zigwin32; the app layer imports the Engine.
// The boundary is structural — a module can only @import what is listed in its
// `imports`, so e.g. `@import("dvui")` or `@import("zigwin32")` inside the
// engine module is a compile error ("no module named ... available").
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zigwin32 = b.dependency("zigwin32", .{});

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

    // App exe (stub until the tray/window tickets land).
    const app_mod = b.createModule(.{
        .root_source_file = b.path("src/app/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "engine", .module = engine },
        },
    });
    const app_exe = b.addExecutable(.{
        .name = "zpulsar",
        .root_module = app_mod,
    });
    b.installArtifact(app_exe);

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
    const test_step = b.step("test", "Run engine and facade tests");
    test_step.dependOn(&b.addRunArtifact(engine_tests).step);
    test_step.dependOn(&b.addRunArtifact(facade_tests).step);
}
