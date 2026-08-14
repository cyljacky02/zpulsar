// PROTOTYPE — throwaway build for the main-window UI prototype (wayfinder ticket #10).
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dvui_dep = b.dependency("dvui", .{
        .target = target,
        .optimize = optimize,
        .backend = .dx11,
        .freetype = false,
        .@"tree-sitter" = false,
        .@"tiny-file-dialogs" = false,
    });

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("dvui", dvui_dep.module("dvui_dx11"));

    const exe = b.addExecutable(.{ .name = "zpulsar-ui-prototype", .root_module = mod });
    exe.subsystem = .Windows;
    exe.win32_manifest = b.path("main.manifest");
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the UI prototype");
    run_step.dependOn(&run_cmd.step);
}
