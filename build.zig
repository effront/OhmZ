const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ohmz",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = false,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run OhmZ scanner");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");

    const test_modules = [_][]const u8{
        "src/stats.zig",
        "src/target.zig",
        "src/packet.zig",
        "src/cookie.zig",
        "src/blackrock.zig",
        "src/throttle.zig",
        "src/banner.zig",
        "src/tls.zig",
        "src/output.zig",
        "src/ports.zig",
        "src/sigs.zig",
    };

    for (test_modules) |mod| {
        const t = b.addTest(.{
            .root_source_file = b.path(mod),
            .target = target,
            .optimize = optimize,
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
