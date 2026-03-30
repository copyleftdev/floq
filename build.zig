const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Version injection
    const options = b.addOptions();
    options.addOption([]const u8, "version", "0.2.0");

    const exe = b.addExecutable(.{
        .name = "floq",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();
    exe.linkSystemLibrary("pcap");
    exe.root_module.addImport("build_options", options.createModule());

    // Strip in release builds
    if (optimize != .Debug) {
        exe.root_module.strip = true;
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run floq");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests.linkLibC();
    tests.linkSystemLibrary("pcap");
    tests.root_module.addImport("build_options", options.createModule());

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
