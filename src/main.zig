const std = @import("std");
const types = @import("types.zig");
const capture = @import("capture.zig");
const ingest = @import("ingest.zig");
const detector_mod = @import("detector.zig");
const allowlist = @import("allowlist.zig");
const output = @import("output.zig");
const spectral = @import("spectral.zig");
const build_options = @import("build_options");

// Signal handling — async-signal-safe atomic flag
var shutdown_requested = std.atomic.Value(bool).init(false);

fn handleSignal(_: c_int) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

const EventSource = union(enum) {
    pcap: capture.CaptureSource,
    jsonl: ingest.JsonlSource,

    pub fn next(self: *EventSource, out_pkt: *capture.Packet) capture.CaptureSource.ReadResult {
        return switch (self.*) {
            .pcap => |*s| s.next(out_pkt),
            .jsonl => |*s| s.next(out_pkt),
        };
    }

    pub fn close(self: *EventSource) void {
        switch (self.*) {
            .pcap => |*s| s.close(),
            .jsonl => |*s| s.close(),
        }
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const config = parseArgs() catch {
        printUsage();
        std.process.exit(1);
    };

    // Install signal handlers for graceful shutdown
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    if (config.output_format == .csv) {
        try output.writeCsvHeader(stdout);
    }

    // Load file-based allowlist if specified
    var extra_allowlist: ?std.ArrayList(allowlist.Entry) = null;
    defer if (extra_allowlist) |*al| al.deinit();

    if (config.allowlist_file) |path| {
        extra_allowlist = allowlist.loadFile(alloc, path) catch |err| {
            stderr.print("error: could not load allowlist: {}\n", .{err}) catch {};
            std.process.exit(1);
        };
    }

    // Open event source
    var src: EventSource = blk: {
        if (config.stdin_mode) {
            break :blk .{ .jsonl = ingest.JsonlSource.init() };
        } else if (config.pcap_file) |path| {
            break :blk .{ .pcap = capture.CaptureSource.openFile(
                @ptrCast(path.ptr),
                if (config.bpf_filter) |f| @ptrCast(f.ptr) else null,
            ) catch {
                stderr.print("error: could not open pcap file\n", .{}) catch {};
                std.process.exit(1);
            } };
        } else if (config.interface) |iface| {
            break :blk .{ .pcap = capture.CaptureSource.openLive(
                @ptrCast(iface.ptr),
                if (config.bpf_filter) |f| @ptrCast(f.ptr) else null,
            ) catch {
                stderr.print("error: could not open interface (try sudo)\n", .{}) catch {};
                std.process.exit(1);
            } };
        } else {
            stderr.print("error: specify -i <interface>, -r <file.pcap>, or --stdin\n", .{}) catch {};
            std.process.exit(1);
        }
    };
    defer src.close();

    var det = detector_mod.Detector.init(alloc, config);
    defer det.deinit();

    if (extra_allowlist) |al| {
        det.extra_allowlist = al.items;
    }

    const is_finite = config.pcap_file != null or config.stdin_mode;

    // Stats
    var packets_processed: u64 = 0;
    var packets_skipped: u64 = 0;
    var alerts_emitted: u64 = 0;
    const start_time = std.time.timestamp();

    // Event loop
    var last_ts: f64 = 0;
    var pkt: capture.Packet = undefined;
    while (!shutdown_requested.load(.acquire)) {
        switch (src.next(&pkt)) {
            .packet => {
                last_ts = pkt.timestamp;
                packets_processed += 1;
                try det.ingest(pkt.flow, pkt.timestamp);

                if (det.shouldAnalyze(pkt.timestamp)) {
                    if (config.verbose) {
                        stderr.print("[verbose] packets={d} flows={d} alerts={d}\n", .{
                            packets_processed, det.flowCount(), alerts_emitted,
                        }) catch {};
                    }

                    var results = try det.analyze(pkt.timestamp, false);
                    defer results.deinit();

                    for (results.items) |result| {
                        try output.writeResult(stdout, result, config.output_format);
                        alerts_emitted += 1;
                    }
                }
            },
            .skipped => {
                packets_skipped += 1;
                continue;
            },
            .eof => {
                if (is_finite) {
                    var results = try det.analyze(last_ts, true);
                    defer results.deinit();
                    for (results.items) |result| {
                        try output.writeResult(stdout, result, config.output_format);
                        alerts_emitted += 1;
                    }
                }
                break;
            },
        }
    }

    // If shutdown by signal on live capture, run final analysis
    if (shutdown_requested.load(.acquire) and !is_finite and last_ts > 0) {
        var results = try det.analyze(last_ts, true);
        defer results.deinit();
        for (results.items) |result| {
            try output.writeResult(stdout, result, config.output_format);
            alerts_emitted += 1;
        }
    }

    // Print stats to stderr
    const elapsed = std.time.timestamp() - start_time;
    output.writeStats(stderr, packets_processed, packets_skipped, det.flowCount(), alerts_emitted, elapsed) catch {};
}

fn parseArgs() !types.Config {
    var config = types.Config{};
    const args = std.process.args();
    var iter = args;
    _ = iter.next();

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-i")) {
            config.interface = iter.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "-r")) {
            config.pcap_file = iter.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "-f")) {
            config.bpf_filter = iter.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "-w")) {
            const val = iter.next() orelse return error.MissingArg;
            config.window_secs = std.fmt.parseFloat(f64, val) catch return error.InvalidArg;
        } else if (std.mem.eql(u8, arg, "-t")) {
            const val = iter.next() orelse return error.MissingArg;
            config.threshold = std.fmt.parseFloat(f64, val) catch return error.InvalidArg;
        } else if (std.mem.eql(u8, arg, "-n")) {
            const val = iter.next() orelse return error.MissingArg;
            config.min_samples = std.fmt.parseInt(usize, val, 10) catch return error.InvalidArg;
        } else if (std.mem.eql(u8, arg, "-a")) {
            const val = iter.next() orelse return error.MissingArg;
            config.analysis_interval = std.fmt.parseFloat(f64, val) catch return error.InvalidArg;
        } else if (std.mem.eql(u8, arg, "--json")) {
            config.output_format = .json;
        } else if (std.mem.eql(u8, arg, "--csv")) {
            config.output_format = .csv;
        } else if (std.mem.eql(u8, arg, "--stdin")) {
            config.stdin_mode = true;
        } else if (std.mem.eql(u8, arg, "--no-allowlist")) {
            config.no_allowlist = true;
        } else if (std.mem.eql(u8, arg, "--allowlist")) {
            config.allowlist_file = iter.next() orelse return error.MissingArg;
        } else if (std.mem.eql(u8, arg, "--max-flows")) {
            const val = iter.next() orelse return error.MissingArg;
            config.max_flows = std.fmt.parseInt(usize, val, 10) catch return error.InvalidArg;
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            config.verbose = true;
        } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
            std.debug.print("floq {s}\n", .{build_options.version});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        } else {
            return error.UnknownArg;
        }
    }

    return config;
}

fn printUsage() void {
    const usage =
        \\floq - C2 beacon detector using Floquet spectral analysis
        \\
        \\USAGE:
        \\  floq -i <interface> [options]
        \\  floq -r <file.pcap> [options]
        \\  floq --stdin [options]
        \\
        \\INPUT MODES:
        \\  -i <iface>         Live capture on interface (requires root)
        \\  -r <file>          Read from pcap file
        \\  --stdin            Read JSONL connection events from stdin
        \\
        \\OPTIONS:
        \\  -f <filter>        BPF filter expression (e.g. "tcp")
        \\  -w <seconds>       Sliding window duration (default: 300)
        \\  -t <0.0-1.0>       Beacon score threshold (default: 0.6)
        \\  -n <count>         Minimum samples per flow (default: 10)
        \\  -a <seconds>       Analysis interval (default: 30)
        \\  --max-flows <N>    Maximum tracked flows (default: 100000)
        \\  --json             JSON output (one object per line)
        \\  --csv              CSV output
        \\  --allowlist <file> Load additional allowlist entries from file
        \\  --no-allowlist     Disable built-in allowlist (NTP, SNMP, etc.)
        \\  -v, --verbose      Periodic stats to stderr
        \\  -V, --version      Show version and exit
        \\  -h, --help         Show this help
        \\
        \\JSONL FORMAT (--stdin):
        \\  {"ts":1234.5,"src":"1.2.3.4","dst":"5.6.7.8","port":443,"proto":"tcp"}
        \\  Supports IPv6: {"src":"2001:db8::1","dst":"::ffff:5.6.7.8","port":80}
        \\  OTel fields: startTimeUnixNano, client.address, server.address, server.port
        \\
        \\ALLOWLIST FILE FORMAT:
        \\  # Comments start with #
        \\  123/udp            # NTP
        \\  10.1.1.1:53/udp    # Internal DNS
        \\
        \\EXAMPLES:
        \\  sudo floq -i eth0 -f "tcp" -t 0.5
        \\  floq -r capture.pcap --json
        \\  floq -r capture.pcap --allowlist custom.txt
        \\  cat flows.jsonl | floq --stdin --json
        \\
    ;
    std.debug.print("{s}", .{usage});
}

test {
    _ = spectral;
    _ = detector_mod;
    _ = ingest;
    _ = @import("allowlist.zig");
}
