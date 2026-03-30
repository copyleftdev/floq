const std = @import("std");
const types = @import("types.zig");
const capture = @import("capture.zig");

/// Reads newline-delimited JSON connection events from stdin.
pub const JsonlSource = struct {
    reader: std.io.BufferedReader(4096, std.fs.File.Reader),
    line_buf: [8192]u8 = undefined,

    pub fn init() JsonlSource {
        const stdin_file = std.io.getStdIn();
        return .{
            .reader = std.io.bufferedReader(stdin_file.reader()),
        };
    }

    pub fn next(self: *JsonlSource, out_pkt: *capture.Packet) capture.CaptureSource.ReadResult {
        const line = self.reader.reader().readUntilDelimiter(&self.line_buf, '\n') catch |err| {
            return switch (err) {
                error.EndOfStream => .eof,
                else => .eof,
            };
        };

        const parsed = parseJsonLine(line) orelse return .skipped;
        out_pkt.* = parsed;
        return .packet;
    }

    pub fn close(_: *JsonlSource) void {}
};

/// Parse a single JSON line into a Packet.
pub fn parseJsonLine(line: []const u8) ?capture.Packet {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) return null;

    var ts: ?f64 = null;
    var src: ?[16]u8 = null;
    var dst: ?[16]u8 = null;
    var port: ?u16 = null;
    var proto: u8 = 6;

    var scanner = std.json.Scanner.initCompleteInput(std.heap.page_allocator, trimmed);
    defer scanner.deinit();

    const first = scanner.next() catch return null;
    if (first != .object_begin) return null;

    while (true) {
        const tok = scanner.next() catch return null;
        switch (tok) {
            .object_end => break,
            .string => |key| {
                if (std.mem.eql(u8, key, "ts")) {
                    ts = readNumber(&scanner);
                } else if (std.mem.eql(u8, key, "startTimeUnixNano")) {
                    if (readString(&scanner)) |nanos_str| {
                        const nanos = std.fmt.parseInt(u64, nanos_str, 10) catch null;
                        if (nanos) |n| {
                            ts = @as(f64, @floatFromInt(n)) / 1_000_000_000.0;
                        }
                    }
                } else if (std.mem.eql(u8, key, "src") or std.mem.eql(u8, key, "client.address")) {
                    if (readString(&scanner)) |s| {
                        src = parseIpAddr(s);
                    }
                } else if (std.mem.eql(u8, key, "dst") or std.mem.eql(u8, key, "server.address")) {
                    if (readString(&scanner)) |s| {
                        dst = parseIpAddr(s);
                    }
                } else if (std.mem.eql(u8, key, "port") or std.mem.eql(u8, key, "server.port")) {
                    if (readNumber(&scanner)) |n| {
                        port = @intFromFloat(n);
                    }
                } else if (std.mem.eql(u8, key, "proto")) {
                    if (readString(&scanner)) |s| {
                        proto = protoFromString(s);
                    }
                } else {
                    skipValue(&scanner);
                }
            },
            else => return null,
        }
    }

    return .{
        .timestamp = ts orelse return null,
        .flow = .{
            .src_addr = src orelse return null,
            .dst_addr = dst orelse return null,
            .dst_port = port orelse return null,
            .protocol = proto,
        },
    };
}

fn readNumber(scanner: *std.json.Scanner) ?f64 {
    const tok = scanner.next() catch return null;
    return switch (tok) {
        .number => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn readString(scanner: *std.json.Scanner) ?[]const u8 {
    const tok = scanner.next() catch return null;
    return switch (tok) {
        .string => |s| s,
        else => null,
    };
}

fn skipValue(scanner: *std.json.Scanner) void {
    const tok = scanner.next() catch return;
    switch (tok) {
        .object_begin => {
            var depth: usize = 1;
            while (depth > 0) {
                const t = scanner.next() catch return;
                switch (t) {
                    .object_begin => depth += 1,
                    .object_end => depth -= 1,
                    else => {},
                }
            }
        },
        .array_begin => {
            var depth: usize = 1;
            while (depth > 0) {
                const t = scanner.next() catch return;
                switch (t) {
                    .array_begin => depth += 1,
                    .array_end => depth -= 1,
                    else => {},
                }
            }
        },
        else => {},
    }
}

/// Parse an IP address string (IPv4 or IPv6) into [16]u8.
pub fn parseIpAddr(s: []const u8) ?[16]u8 {
    // Try IPv4 first
    if (parseIpv4(s)) |v4| return types.ipv4Mapped(v4);
    // Try IPv6
    return parseIpv6(s);
}

fn parseIpv4(s: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var idx: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (idx >= 4) return null;
        parts[idx] = std.fmt.parseInt(u8, part, 10) catch return null;
        idx += 1;
    }
    if (idx != 4) return null;
    return @as(u32, parts[0]) << 24 | @as(u32, parts[1]) << 16 | @as(u32, parts[2]) << 8 | parts[3];
}

fn parseIpv6(s: []const u8) ?[16]u8 {
    var result = [_]u8{0} ** 16;
    var groups: [8]u16 = .{ 0, 0, 0, 0, 0, 0, 0, 0 };
    var group_count: usize = 0;
    var expand_pos: ?usize = null;

    var it = std.mem.splitSequence(u8, s, ":");
    while (it.next()) |part| {
        if (part.len == 0) {
            // "::" expansion point
            if (expand_pos != null) {
                // Only one :: allowed; second empty part after :: is ok
                continue;
            }
            expand_pos = group_count;
            continue;
        }
        if (group_count >= 8) return null;
        groups[group_count] = std.fmt.parseInt(u16, part, 16) catch return null;
        group_count += 1;
    }

    if (expand_pos) |pos| {
        // Shift groups after :: to the end
        const tail_len = group_count - pos;
        const shift = 8 - group_count;
        var i: usize = 0;
        while (i < tail_len) : (i += 1) {
            groups[7 - i] = groups[group_count - 1 - i];
        }
        i = pos;
        while (i < pos + shift) : (i += 1) {
            groups[i] = 0;
        }
    } else if (group_count != 8) {
        return null;
    }

    for (0..8) |i| {
        result[i * 2] = @intCast(groups[i] >> 8);
        result[i * 2 + 1] = @intCast(groups[i] & 0xff);
    }
    return result;
}

fn protoFromString(s: []const u8) u8 {
    if (std.mem.eql(u8, s, "tcp")) return 6;
    if (std.mem.eql(u8, s, "udp")) return 17;
    if (std.mem.eql(u8, s, "icmp")) return 1;
    return 6;
}

// --- Tests ---

test "parseIpAddr: ipv4" {
    const addr = parseIpAddr("10.0.0.1").?;
    try std.testing.expect(types.isIpv4Mapped(addr));
    try std.testing.expectEqual(addr[12], 10);
    try std.testing.expectEqual(addr[15], 1);
}

test "parseIpAddr: ipv6 full" {
    const addr = parseIpAddr("2001:db8:0:0:0:0:0:1").?;
    try std.testing.expect(!types.isIpv4Mapped(addr));
    try std.testing.expectEqual(addr[0], 0x20);
    try std.testing.expectEqual(addr[1], 0x01);
    try std.testing.expectEqual(addr[15], 0x01);
}

test "parseIpAddr: ipv6 compressed" {
    const addr = parseIpAddr("2001:db8::1").?;
    try std.testing.expect(!types.isIpv4Mapped(addr));
    try std.testing.expectEqual(addr[0], 0x20);
    try std.testing.expectEqual(addr[1], 0x01);
    try std.testing.expectEqual(addr[15], 0x01);
}

test "parseIpAddr: invalid" {
    try std.testing.expect(parseIpAddr("not.an.ip") == null);
    try std.testing.expect(parseIpAddr("1.2.3") == null);
    try std.testing.expect(parseIpAddr("256.1.1.1") == null);
}

test "parseJsonLine: simple format" {
    const line = "{\"ts\":1234567890.5,\"src\":\"10.0.0.1\",\"dst\":\"192.168.1.1\",\"port\":443,\"proto\":\"tcp\"}";
    const pkt = parseJsonLine(line).?;
    try std.testing.expectApproxEqAbs(pkt.timestamp, 1234567890.5, 0.001);
    try std.testing.expect(types.isIpv4Mapped(pkt.flow.src_addr));
    try std.testing.expectEqual(pkt.flow.dst_port, 443);
    try std.testing.expectEqual(pkt.flow.protocol, 6);
}

test "parseJsonLine: missing fields returns null" {
    try std.testing.expect(parseJsonLine("{\"ts\":1234}") == null);
    try std.testing.expect(parseJsonLine("") == null);
    try std.testing.expect(parseJsonLine("not json") == null);
}
