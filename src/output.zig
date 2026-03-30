const std = @import("std");
const types = @import("types.zig");

const Writer = std.fs.File.Writer;

pub fn writeResult(writer: Writer, result: types.BeaconResult, format: types.Config.OutputFormat) !void {
    switch (format) {
        .human => try writeHuman(writer, result),
        .json => try writeJson(writer, result),
        .csv => try writeCsv(writer, result),
    }
}

pub fn writeCsvHeader(writer: Writer) !void {
    try writer.writeAll("score,src_ip,dst_ip,dst_port,proto,interval,jitter,lsr,acf,samples\n");
}

fn writeHuman(writer: Writer, r: types.BeaconResult) !void {
    try writer.print("[FLOQ] score={d:.3}  ", .{r.score});
    try types.formatAddr(r.flow.src_addr, writer);
    try writer.writeAll(" -> ");
    try types.formatAddr(r.flow.dst_addr, writer);
    try writer.print(":{d}/{s}  interval={d:.1}s  jitter={d:.3}  lsr={d:.3}  acf={d:.3}  n={d}\n", .{
        r.flow.dst_port,
        types.protocolName(r.flow.protocol),
        r.estimated_interval,
        r.jitter_ratio,
        r.lsr,
        r.autocorrelation_peak,
        r.sample_count,
    });
}

fn writeJson(writer: Writer, r: types.BeaconResult) !void {
    try writer.print("{{\"score\":{d:.4},\"src\":\"", .{r.score});
    try types.formatAddr(r.flow.src_addr, writer);
    try writer.print("\",\"dst\":\"", .{});
    try types.formatAddr(r.flow.dst_addr, writer);
    try writer.print("\",\"port\":{d},\"proto\":\"{s}\",\"interval\":{d:.2},\"jitter\":{d:.4},\"lsr\":{d:.4},\"acf\":{d:.4},\"samples\":{d}}}\n", .{
        r.flow.dst_port,
        types.protocolName(r.flow.protocol),
        r.estimated_interval,
        r.jitter_ratio,
        r.lsr,
        r.autocorrelation_peak,
        r.sample_count,
    });
}

fn writeCsv(writer: Writer, r: types.BeaconResult) !void {
    try writer.print("{d:.4},", .{r.score});
    try types.formatAddr(r.flow.src_addr, writer);
    try writer.writeByte(',');
    try types.formatAddr(r.flow.dst_addr, writer);
    try writer.print(",{d},{s},{d:.2},{d:.4},{d:.4},{d:.4},{d}\n", .{
        r.flow.dst_port,
        types.protocolName(r.flow.protocol),
        r.estimated_interval,
        r.jitter_ratio,
        r.lsr,
        r.autocorrelation_peak,
        r.sample_count,
    });
}

pub fn writeStats(writer: anytype, packets_processed: u64, packets_skipped: u64, flows_active: usize, alerts_emitted: u64, elapsed: i64) !void {
    try writer.print("\n--- floq stats ---\n", .{});
    try writer.print("duration:  {d}s\n", .{elapsed});
    try writer.print("packets:   {d} processed, {d} skipped\n", .{ packets_processed, packets_skipped });
    try writer.print("flows:     {d} active\n", .{flows_active});
    try writer.print("alerts:    {d}\n", .{alerts_emitted});
}
