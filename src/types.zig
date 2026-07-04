const std = @import("std");

// IPv4-mapped prefix: 10 zero bytes + 0xff 0xff
const v4_prefix = [10]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
const v4_marker = [2]u8{ 0xff, 0xff };

/// Map an IPv4 u32 address to a [16]u8 IPv4-mapped IPv6 address.
pub fn ipv4Mapped(addr: u32) [16]u8 {
    return v4_prefix ++ v4_marker ++ [4]u8{
        @intCast((addr >> 24) & 0xff),
        @intCast((addr >> 16) & 0xff),
        @intCast((addr >> 8) & 0xff),
        @intCast(addr & 0xff),
    };
}

pub fn isIpv4Mapped(addr: [16]u8) bool {
    return std.mem.eql(u8, addr[0..10], &v4_prefix) and
        addr[10] == 0xff and addr[11] == 0xff;
}

/// Format an address as IPv4 dotted-decimal or IPv6 colon-hex.
pub fn formatAddr(addr: [16]u8, writer: anytype) !void {
    if (isIpv4Mapped(addr)) {
        try writer.print("{}.{}.{}.{}", .{ addr[12], addr[13], addr[14], addr[15] });
    } else {
        var i: usize = 0;
        while (i < 16) : (i += 2) {
            if (i > 0) try writer.writeByte(':');
            const word = @as(u16, addr[i]) << 8 | addr[i + 1];
            try writer.print("{x}", .{word});
        }
    }
}

/// A tracked connection flow identified by (src, dst, port).
pub const FlowKey = struct {
    src_addr: [16]u8,
    dst_addr: [16]u8,
    dst_port: u16,
    protocol: u8,

    pub fn format(self: FlowKey, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        try formatAddr(self.src_addr, writer);
        try writer.writeAll("->");
        try formatAddr(self.dst_addr, writer);
        try writer.print(":{d}/{s}", .{ self.dst_port, protocolName(self.protocol) });
    }
};

pub fn protocolName(proto: u8) []const u8 {
    return switch (proto) {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmp6",
        else => "???",
    };
}

/// Result of spectral analysis on a flow's timing data.
pub const BeaconResult = struct {
    flow: FlowKey,
    sample_count: usize,
    lsr: f64,
    estimated_interval: f64,
    period_significance: f64,
    jitter_ratio: f64,
    score: f64,
};

/// Configuration for the detector.
pub const Config = struct {
    interface: ?[]const u8 = null,
    bpf_filter: ?[]const u8 = null,
    window_secs: f64 = 300.0,
    min_samples: usize = 10,
    threshold: f64 = 0.6,
    analysis_interval: f64 = 30.0,
    pcap_file: ?[]const u8 = null,
    stdin_mode: bool = false,
    no_allowlist: bool = false,
    output_format: OutputFormat = .human,
    max_flows: usize = 100_000,
    verbose: bool = false,
    allowlist_file: ?[]const u8 = null,

    pub const OutputFormat = enum { human, json, csv };
};
