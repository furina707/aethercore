const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // 单一统一原生二进制
    const exe = b.addExecutable(.{
        .name = "aethercore",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    exe.root_module.link_libc = true;

    // 平台链接配置
    if (target.result.os.tag == .linux) {
        // Linux GTK4 原生 GUI 支持
        exe.root_module.linkSystemLibrary("gtk-4", .{});
        exe.root_module.linkSystemLibrary("gobject-2.0", .{});
        exe.root_module.linkSystemLibrary("gio-2.0", .{});
        exe.root_module.linkSystemLibrary("glib-2.0", .{});
    } else if (target.result.os.tag == .windows) {
        // Windows DWM 高清渲染与网络支持
        exe.root_module.linkSystemLibrary("user32", .{});
        exe.root_module.linkSystemLibrary("gdi32", .{});
        exe.root_module.linkSystemLibrary("dwmapi", .{});
        exe.root_module.linkSystemLibrary("shcore", .{});
    }

    b.installArtifact(exe);

    // 运行步骤
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "运行 aethercore");
    run_step.dependOn(&run_cmd.step);
}
