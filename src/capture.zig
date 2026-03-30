const std = @import("std");
const types = @import("types.zig");

const c = @cImport({
    @cInclude("pcap/pcap.h");
});

const PCAP_ERRBUF_SIZE = 256;

pub const Packet = struct {
    timestamp: f64,
    flow: types.FlowKey,
};

pub const CaptureSource = struct {
    handle: *c.pcap_t,
    datalink: c_int,

    pub fn openLive(device: [*:0]const u8, bpf_filter: ?[*:0]const u8) !CaptureSource {
        var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;
        const handle = c.pcap_open_live(device, 128, 1, 100, &errbuf) orelse {
            std.debug.print("pcap_open_live: {s}\n", .{@as([*:0]u8, @ptrCast(&errbuf))});
            return error.PcapOpenFailed;
        };
        if (bpf_filter) |filter| {
            try applyFilter(handle, filter);
        }
        return .{ .handle = handle, .datalink = c.pcap_datalink(handle) };
    }

    pub fn openFile(path: [*:0]const u8, bpf_filter: ?[*:0]const u8) !CaptureSource {
        var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;
        const handle = c.pcap_open_offline(path, &errbuf) orelse {
            std.debug.print("pcap_open_offline: {s}\n", .{@as([*:0]u8, @ptrCast(&errbuf))});
            return error.PcapOpenFailed;
        };
        if (bpf_filter) |filter| {
            try applyFilter(handle, filter);
        }
        return .{ .handle = handle, .datalink = c.pcap_datalink(handle) };
    }

    fn applyFilter(handle: *c.pcap_t, filter: [*:0]const u8) !void {
        var fp: c.struct_bpf_program = undefined;
        if (c.pcap_compile(handle, &fp, filter, 1, 0) == -1) {
            std.debug.print("pcap_compile: {s}\n", .{c.pcap_geterr(handle)});
            return error.BpfCompileFailed;
        }
        defer c.pcap_freecode(&fp);
        if (c.pcap_setfilter(handle, &fp) == -1) {
            std.debug.print("pcap_setfilter: {s}\n", .{c.pcap_geterr(handle)});
            return error.BpfFilterFailed;
        }
    }

    pub const ReadResult = enum { packet, skipped, eof };

    pub fn next(self: *CaptureSource, out_pkt: *Packet) ReadResult {
        var header: *c.struct_pcap_pkthdr = undefined;
        var data: [*]const u8 = undefined;

        const rc = c.pcap_next_ex(self.handle, @ptrCast(&header), @ptrCast(&data));
        if (rc != 1) return .eof;

        const ts = @as(f64, @floatFromInt(header.ts.tv_sec)) +
            @as(f64, @floatFromInt(header.ts.tv_usec)) / 1_000_000.0;

        const flow = parsePacket(data, header.caplen, self.datalink) orelse return .skipped;

        out_pkt.* = .{ .timestamp = ts, .flow = flow };
        return .packet;
    }

    pub fn close(self: *CaptureSource) void {
        c.pcap_close(self.handle);
    }
};

/// Parse raw packet into a FlowKey. Handles Ethernet + VLAN + IPv4/IPv6 + TCP/UDP.
fn parsePacket(data: [*]const u8, len: u32, datalink: c_int) ?types.FlowKey {
    var offset: u32 = 0;
    var ethertype: u16 = 0;

    // Link layer
    if (datalink == 1) { // DLT_EN10MB
        if (len < 14) return null;
        ethertype = @as(u16, data[12]) << 8 | data[13];
        offset = 14;

        // Strip 802.1Q / QinQ VLAN tags
        while (ethertype == 0x8100 or ethertype == 0x88A8) {
            if (len < offset + 4) return null;
            ethertype = @as(u16, data[offset + 2]) << 8 | data[offset + 3];
            offset += 4;
        }
    } else if (datalink == 113) { // DLT_LINUX_SLL
        if (len < 16) return null;
        ethertype = @as(u16, data[14]) << 8 | data[15];
        offset = 16;
    } else {
        return null;
    }

    return switch (ethertype) {
        0x0800 => parseIpv4(data, len, offset),
        0x86DD => parseIpv6(data, len, offset),
        else => null,
    };
}

fn parseIpv4(data: [*]const u8, len: u32, offset: u32) ?types.FlowKey {
    if (len < offset + 20) return null;
    const ip = data + offset;

    const ihl: u32 = @as(u32, ip[0] & 0x0f) * 4;
    if (ihl < 20) return null;
    if (len < offset + ihl) return null;

    const protocol = ip[9];
    const src_addr = types.ipv4Mapped(
        @as(u32, ip[12]) << 24 | @as(u32, ip[13]) << 16 | @as(u32, ip[14]) << 8 | ip[15],
    );
    const dst_addr = types.ipv4Mapped(
        @as(u32, ip[16]) << 24 | @as(u32, ip[17]) << 16 | @as(u32, ip[18]) << 8 | ip[19],
    );

    if (protocol != 6 and protocol != 17) {
        return .{ .src_addr = src_addr, .dst_addr = dst_addr, .dst_port = 0, .protocol = protocol };
    }

    const transport_offset = offset + ihl;
    if (len < transport_offset + 4) return null;
    const transport = data + transport_offset;
    const dst_port = @as(u16, transport[2]) << 8 | transport[3];

    return .{ .src_addr = src_addr, .dst_addr = dst_addr, .dst_port = dst_port, .protocol = protocol };
}

fn parseIpv6(data: [*]const u8, len: u32, offset: u32) ?types.FlowKey {
    if (len < offset + 40) return null;
    const ip6 = data + offset;

    const next_header = ip6[6];
    var src_addr: [16]u8 = undefined;
    var dst_addr: [16]u8 = undefined;
    @memcpy(&src_addr, ip6[8..24]);
    @memcpy(&dst_addr, ip6[24..40]);

    if (next_header != 6 and next_header != 17) {
        return .{ .src_addr = src_addr, .dst_addr = dst_addr, .dst_port = 0, .protocol = next_header };
    }

    const transport_offset = offset + 40;
    if (len < transport_offset + 4) return null;
    const transport = data + transport_offset;
    const dst_port = @as(u16, transport[2]) << 8 | transport[3];

    return .{ .src_addr = src_addr, .dst_addr = dst_addr, .dst_port = dst_port, .protocol = next_header };
}
