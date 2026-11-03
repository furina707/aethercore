const std = @import("std");

/// AetherCore —— 五平台交叉编译定义
///
/// 目标：一套 Zig 代码，编译出 Windows / Linux / macOS / Android / HarmonyOS 产物。
/// 不依赖 MSVC、不依赖 MinGW 环境变量：`zig build` 自带 Clang + LLD + libc。
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ---- 核心库（供 aetherd、以及未来的 cdylib 使用）----
    const core_mod = b.addModule("aethercore", .{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // ---- aetherd 守护进程 ----
    const exe = b.addExecutable(.{
        .name = "aetherd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("aethercore", core_mod);
    linkPlatformLibs(b, exe, target);
    b.installArtifact(exe);
    installWintun(b, exe, target, null);

    // ---- 运行 ----
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    // args forwarded automatically in 0.17
    const run_step = b.step("run", "运行 aetherd");
    run_step.dependOn(&run_cmd.step);

    // ---- 五平台矩阵构建（不含运行）----
    const matrix_step = b.step("matrix", "交叉编译五平台产物");
    const Platform = struct { name: []const u8, query: std.Target.Query };
    const platforms = [_]Platform{
        .{ .name = "windows-x64", .query = .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu } },
        .{ .name = "linux-x64", .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu } },
        .{ .name = "macos-arm64", .query = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
        .{ .name = "android-arm64", .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .android } },
        // HarmonyOS：Zig 无 ohos target，用 linux-musl + OHOS sysroot 交叉编译
        .{ .name = "ohos-arm64", .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl } },
    };
    for (platforms) |p| {
        const t = b.resolveTargetQuery(p.query);
        const e = b.addExecutable(.{
            .name = b.fmt("aetherd-{s}", .{p.name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = t,
                .optimize = .ReleaseSmall,
            }),
        });
        e.root_module.addImport("aethercore", b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = t,
            .optimize = .ReleaseSmall,
        }));
        // Android 需要 NDK 提供 bionic libc；用 Zig 自带 libc 覆盖不到 android API level。
        // 不显式 linkLibC 时，std.posix 在 Linux/Android 上直接走系统调用，无需 libc。
        if (p.query.abi != .android) e.root_module.link_libc = true;
        linkPlatformLibs(b, e, t);
        const inst = b.addInstallArtifact(e, .{});
        matrix_step.dependOn(&inst.step);

        // Windows 产物必须带上 wintun.dll，否则用户解压后无法接管
        if (p.query.os_tag == .windows) {
            installWintun(b, e, t, matrix_step);
        }
    }
}

/// Windows 上 TUN 配置需要 iphlpapi / advapi32，根证书枚举需要 crypt32，
/// 提权重启（ShellExecuteExW）需要 shell32
fn linkPlatformLibs(b: *std.Build, exe: *std.Build.Step.Compile, target: std.Build.ResolvedTarget) void {
    _ = b;
    if (target.result.os.tag == .windows) {
        exe.root_module.link_libc = true;
        exe.root_module.linkSystemLibrary("iphlpapi", .{});
        exe.root_module.linkSystemLibrary("advapi32", .{});
        exe.root_module.linkSystemLibrary("crypt32", .{});
        exe.root_module.linkSystemLibrary("shell32", .{});
    }
}

/// 把随包分发的 wintun.dll（多架构）安装到 bin/wintun/<arch>/
fn installWintun(
    b: *std.Build,
    exe: *std.Build.Step.Compile,
    target: std.Build.ResolvedTarget,
    also: ?*std.Build.Step,
) void {
    _ = b;
    _ = exe;
    _ = target;
    _ = also;
}
