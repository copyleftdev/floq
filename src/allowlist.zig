const std = @import("std");
const types = @import("types.zig");

pub const Entry = struct {
    dst_port: ?u16 = null,
    dst_addr: ?[16]u8 = null,
    protocol: ?u8 = null,
};

/// Known periodic services that produce false positive beacon alerts.
const defaults = [_]Entry{
    .{ .dst_port = 123, .protocol = 17 }, // NTP
    .{ .dst_port = 161, .protocol = 17 }, // SNMP
    .{ .dst_port = 53, .dst_addr = types.ipv4Mapped(0x08080808) }, // 8.8.8.8
    .{ .dst_port = 53, .dst_addr = types.ipv4Mapped(0x08080404) }, // 8.8.4.4
    .{ .dst_port = 53, .dst_addr = types.ipv4Mapped(0x01010101) }, // 1.1.1.1
    .{ .dst_port = 53, .dst_addr = types.ipv4Mapped(0x01000001) }, // 1.0.0.1
};

fn matchEntry(e: Entry, flow: types.FlowKey) bool {
    if (e.dst_port) |p| {
        if (flow.dst_port != p) return false;
    }
    if (e.dst_addr) |a| {
        if (!std.mem.eql(u8, &flow.dst_addr, &a)) return false;
    }
    if (e.protocol) |pr| {
        if (flow.protocol != pr) return false;
    }
    return true;
}

/// Returns true if the flow matches a known periodic service.
pub fn isAllowed(flow: types.FlowKey, extra: ?[]const Entry) bool {
    for (&defaults) |e| {
        if (matchEntry(e, flow)) return true;
    }
    if (extra) |entries| {
        for (entries) |e| {
            if (matchEntry(e, flow)) return true;
        }
    }
    return false;
}

/// Load allowlist entries from a file. Format: [ip:]port/proto, # comments.
pub fn loadFile(alloc: std.mem.Allocator, path: []const u8) !std.ArrayList(Entry) {
    var entries = std.ArrayList(Entry).init(alloc);
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    var buf_reader = std.io.bufferedReader(file.reader());
    var line_buf: [1024]u8 = undefined;

    while (true) {
        const line = buf_reader.reader().readUntilDelimiter(&line_buf, '\n') catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (parseEntry(trimmed)) |entry| {
            try entries.append(entry);
        }
    }
    return entries;
}

fn parseEntry(line: []const u8) ?Entry {
    var entry = Entry{};
    // Split on '/' for protocol
    var slash_it = std.mem.splitScalar(u8, line, '/');
    const addr_port = slash_it.next() orelse return null;
    if (slash_it.next()) |proto_str| {
        const trimmed = std.mem.trim(u8, proto_str, " \t");
        if (std.mem.eql(u8, trimmed, "tcp")) {
            entry.protocol = 6;
        } else if (std.mem.eql(u8, trimmed, "udp")) {
            entry.protocol = 17;
        }
    }
    // Split addr_port on ':' for optional IP
    if (std.mem.lastIndexOfScalar(u8, addr_port, ':')) |colon_pos| {
        const ip_str = addr_port[0..colon_pos];
        const port_str = addr_port[colon_pos + 1 ..];
        // Try IPv4
        const ingest = @import("ingest.zig");
        entry.dst_addr = ingest.parseIpAddr(ip_str);
        entry.dst_port = std.fmt.parseInt(u16, port_str, 10) catch return null;
    } else {
        entry.dst_port = std.fmt.parseInt(u16, addr_port, 10) catch return null;
    }
    return entry;
}

// --- Tests ---

test "allowlist: SNMP filtered" {
    const flow = types.FlowKey{ .src_addr = types.ipv4Mapped(0x0A000001), .dst_addr = types.ipv4Mapped(0xC0A80001), .dst_port = 161, .protocol = 17 };
    try std.testing.expect(isAllowed(flow, null));
}

test "allowlist: NTP filtered" {
    const flow = types.FlowKey{ .src_addr = types.ipv4Mapped(0x0A000001), .dst_addr = types.ipv4Mapped(0x0A000002), .dst_port = 123, .protocol = 17 };
    try std.testing.expect(isAllowed(flow, null));
}

test "allowlist: DNS to 8.8.8.8 filtered" {
    const flow = types.FlowKey{ .src_addr = types.ipv4Mapped(0x0A000001), .dst_addr = types.ipv4Mapped(0x08080808), .dst_port = 53, .protocol = 17 };
    try std.testing.expect(isAllowed(flow, null));
}

test "allowlist: DNS to random server NOT filtered" {
    const flow = types.FlowKey{ .src_addr = types.ipv4Mapped(0x0A000001), .dst_addr = types.ipv4Mapped(0xC0A80001), .dst_port = 53, .protocol = 17 };
    try std.testing.expect(!isAllowed(flow, null));
}

test "allowlist: HTTPS traffic NOT filtered" {
    const flow = types.FlowKey{ .src_addr = types.ipv4Mapped(0x0A000001), .dst_addr = types.ipv4Mapped(0xC0A80001), .dst_port = 443, .protocol = 6 };
    try std.testing.expect(!isAllowed(flow, null));
}
