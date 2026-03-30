const std = @import("std");
const types = @import("types.zig");
const spectral = @import("spectral.zig");
const allowlist = @import("allowlist.zig");

const Allocator = std.mem.Allocator;

/// Per-flow state: sliding window of packet timestamps.
const FlowState = struct {
    timestamps: std.ArrayList(f64),
    last_alert: f64 = 0,
    last_seen: f64 = 0,

    fn init(alloc: Allocator) FlowState {
        return .{ .timestamps = std.ArrayList(f64).init(alloc) };
    }

    fn deinit(self: *FlowState) void {
        self.timestamps.deinit();
    }
};

/// Beacon detector: tracks flows and runs spectral analysis on their timing.
pub const Detector = struct {
    flows: std.AutoHashMap(types.FlowKey, FlowState),
    alloc: Allocator,
    config: types.Config,
    extra_allowlist: ?[]const allowlist.Entry = null,
    last_analysis: f64 = 0,

    pub fn init(alloc: Allocator, config: types.Config) Detector {
        return .{
            .flows = std.AutoHashMap(types.FlowKey, FlowState).init(alloc),
            .alloc = alloc,
            .config = config,
        };
    }

    pub fn deinit(self: *Detector) void {
        var it = self.flows.valueIterator();
        while (it.next()) |state| {
            state.deinit();
        }
        self.flows.deinit();
    }

    /// Ingest a packet timestamp for a flow.
    pub fn ingest(self: *Detector, flow: types.FlowKey, timestamp: f64) !void {
        if (!self.config.no_allowlist and allowlist.isAllowed(flow, self.extra_allowlist)) return;

        // If new flow and at capacity, evict oldest
        if (self.flows.get(flow) == null and self.flows.count() >= self.config.max_flows) {
            self.evictOldestFlow();
        }

        const result = try self.flows.getOrPut(flow);
        if (!result.found_existing) {
            result.value_ptr.* = FlowState.init(self.alloc);
        }
        result.value_ptr.last_seen = timestamp;
        try result.value_ptr.timestamps.append(timestamp);
    }

    /// Run analysis on all flows. Returns beacon results exceeding threshold.
    pub fn analyze(self: *Detector, now: f64, final: bool) !std.ArrayList(types.BeaconResult) {
        var results = std.ArrayList(types.BeaconResult).init(self.alloc);

        // Evict silent flows (two-pass)
        var to_evict = std.ArrayList(types.FlowKey).init(self.alloc);
        defer to_evict.deinit();
        const eviction_cutoff = self.config.window_secs * 2;

        var it = self.flows.iterator();
        while (it.next()) |entry| {
            const flow = entry.key_ptr.*;
            var state = entry.value_ptr;

            if (now - state.last_seen > eviction_cutoff) {
                try to_evict.append(flow);
                continue;
            }

            evictOld(&state.timestamps, now - self.config.window_secs);

            const ts = state.timestamps.items;
            if (ts.len < self.config.min_samples) continue;

            const lsr = spectral.levelSpacingRatio(ts) orelse continue;
            const periodicity = spectral.detectPeriodicity(ts);
            const jitter = spectral.jitterRatio(ts);
            const score = spectral.beaconScore(lsr, periodicity.peak, jitter);

            if (score >= self.config.threshold) {
                const cooldown = self.config.analysis_interval * 3;
                if (!final and (now - state.last_alert) < cooldown) continue;

                state.last_alert = now;
                try results.append(.{
                    .flow = flow,
                    .sample_count = ts.len,
                    .lsr = lsr,
                    .estimated_interval = periodicity.interval,
                    .autocorrelation_peak = periodicity.peak,
                    .jitter_ratio = jitter,
                    .score = score,
                });
            }
        }

        for (to_evict.items) |key| {
            if (self.flows.getPtr(key)) |state| {
                state.deinit();
            }
            _ = self.flows.remove(key);
        }

        self.last_analysis = now;
        return results;
    }

    pub fn shouldAnalyze(self: *const Detector, now: f64) bool {
        return (now - self.last_analysis) >= self.config.analysis_interval;
    }

    pub fn flowCount(self: *const Detector) usize {
        return self.flows.count();
    }

    fn evictOldestFlow(self: *Detector) void {
        var oldest_ts: f64 = std.math.inf(f64);
        var oldest_key: ?types.FlowKey = null;

        var it = self.flows.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_seen < oldest_ts) {
                oldest_ts = entry.value_ptr.last_seen;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.flows.getPtr(key)) |state| {
                state.deinit();
            }
            _ = self.flows.remove(key);
        }
    }

    fn evictOld(list: *std.ArrayList(f64), cutoff: f64) void {
        var start: usize = 0;
        while (start < list.items.len and list.items[start] < cutoff) {
            start += 1;
        }
        if (start > 0) {
            std.mem.copyForwards(f64, list.items[0 .. list.items.len - start], list.items[start..]);
            list.shrinkRetainingCapacity(list.items.len - start);
        }
    }
};

test "detector: periodic flow triggers alert" {
    const alloc = std.testing.allocator;
    var config = types.Config{};
    config.min_samples = 5;
    config.threshold = 0.5;
    config.window_secs = 1000;
    config.no_allowlist = true;

    var detector = Detector.init(alloc, config);
    defer detector.deinit();

    const flow = types.FlowKey{
        .src_addr = types.ipv4Mapped(0x0A000001),
        .dst_addr = types.ipv4Mapped(0xC0A80001),
        .dst_port = 443,
        .protocol = 6,
    };

    for (0..20) |i| {
        try detector.ingest(flow, @as(f64, @floatFromInt(i)) * 60.0);
    }

    var results = try detector.analyze(1200.0, true);
    defer results.deinit();

    try std.testing.expect(results.items.len > 0);
    try std.testing.expect(results.items[0].score >= 0.5);
}

test "detector: alert cooldown prevents duplicates" {
    const alloc = std.testing.allocator;
    var config = types.Config{};
    config.min_samples = 5;
    config.threshold = 0.5;
    config.window_secs = 1000;
    config.analysis_interval = 30;
    config.no_allowlist = true;

    var detector = Detector.init(alloc, config);
    defer detector.deinit();

    const flow = types.FlowKey{
        .src_addr = types.ipv4Mapped(0x0A000001),
        .dst_addr = types.ipv4Mapped(0xC0A80001),
        .dst_port = 443,
        .protocol = 6,
    };

    for (0..20) |i| {
        try detector.ingest(flow, @as(f64, @floatFromInt(i)) * 60.0);
    }

    var r1 = try detector.analyze(1200.0, false);
    defer r1.deinit();
    try std.testing.expect(r1.items.len > 0);

    var r2 = try detector.analyze(1210.0, false);
    defer r2.deinit();
    try std.testing.expect(r2.items.len == 0);

    for (20..25) |i| {
        try detector.ingest(flow, @as(f64, @floatFromInt(i)) * 60.0);
    }
    var r3 = try detector.analyze(1300.0, false);
    defer r3.deinit();
    try std.testing.expect(r3.items.len > 0);
}

test "detector: allowlist filters known services" {
    const alloc = std.testing.allocator;
    var config = types.Config{};
    config.min_samples = 5;
    config.threshold = 0.3;
    config.window_secs = 1000;

    var detector = Detector.init(alloc, config);
    defer detector.deinit();

    const snmp_flow = types.FlowKey{
        .src_addr = types.ipv4Mapped(0x0A000001),
        .dst_addr = types.ipv4Mapped(0xC0A80001),
        .dst_port = 161,
        .protocol = 17,
    };

    for (0..20) |i| {
        try detector.ingest(snmp_flow, @as(f64, @floatFromInt(i)) * 60.0);
    }

    try std.testing.expect(detector.flows.count() == 0);
}

test "detector: flow cap evicts oldest" {
    const alloc = std.testing.allocator;
    var config = types.Config{};
    config.max_flows = 3;
    config.no_allowlist = true;
    config.window_secs = 1000;

    var detector = Detector.init(alloc, config);
    defer detector.deinit();

    // Insert 4 flows — should evict the oldest when 4th arrives
    for (0..4) |i| {
        const flow = types.FlowKey{
            .src_addr = types.ipv4Mapped(0x0A000001),
            .dst_addr = types.ipv4Mapped(@as(u32, @intCast(i + 1))),
            .dst_port = 443,
            .protocol = 6,
        };
        try detector.ingest(flow, @as(f64, @floatFromInt(i)) * 10.0);
    }

    try std.testing.expect(detector.flowCount() == 3);
}
