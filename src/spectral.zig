const std = @import("std");
const math = std.math;

/// Compute the level spacing ratio (LSR) from a sorted sequence of timestamps.
///
/// Given inter-arrival times s_i = t_{i+1} - t_i, compute:
///   r_i = min(s_i, s_{i+1}) / max(s_i, s_{i+1})
///
/// Mean r ≈ 0.386 for Poisson (random/no structure)
/// Mean r ≈ 0.530 for GOE (correlated/structured — beacon-like)
///
/// Derived from quantum chaos diagnostics: Sachdev-Ye-Kitaev spectral statistics.
pub fn levelSpacingRatio(timestamps: []const f64) ?f64 {
    if (timestamps.len < 3) return null;

    // Compute inter-arrival times (spacings)
    var sum: f64 = 0.0;
    var count: usize = 0;

    var i: usize = 0;
    while (i + 2 < timestamps.len) : (i += 1) {
        const s1 = timestamps[i + 1] - timestamps[i];
        const s2 = timestamps[i + 2] - timestamps[i + 1];

        if (s1 <= 0 or s2 <= 0) continue;

        const r = @min(s1, s2) / @max(s1, s2);
        sum += r;
        count += 1;
    }

    if (count == 0) return null;
    return sum / @as(f64, @floatFromInt(count));
}

/// Compute the autocorrelation of inter-arrival times at a given lag.
/// Returns a value in [-1, 1] where 1 indicates perfect periodic correlation.
fn autocorrelation(spacings: []const f64, lag: usize, mean: f64) f64 {
    if (lag >= spacings.len) return 0;

    var num: f64 = 0.0;
    var den: f64 = 0.0;

    for (spacings) |s| {
        const d = s - mean;
        den += d * d;
    }
    if (den == 0) return 1.0; // zero variance = perfectly periodic

    var i: usize = 0;
    while (i + lag < spacings.len) : (i += 1) {
        num += (spacings[i] - mean) * (spacings[i + lag] - mean);
    }

    return num / den;
}

/// Find the dominant period via autocorrelation peak detection.
/// Returns (estimated_interval, peak_strength).
///
/// Inspired by Floquet quasi-energy analysis: periodic drives create
/// discrete peaks in the autocorrelation function, analogous to
/// quasi-energy degeneracies in the Floquet spectrum.
pub fn detectPeriodicity(timestamps: []const f64) struct { interval: f64, peak: f64 } {
    if (timestamps.len < 4) return .{ .interval = 0, .peak = 0 };

    const n_spacings = timestamps.len - 1;

    // Compute inter-arrival times
    var spacings_buf: [4096]f64 = undefined;
    const spacings = spacings_buf[0..@min(n_spacings, 4096)];

    var sum: f64 = 0.0;
    for (0..spacings.len) |i| {
        spacings[i] = timestamps[i + 1] - timestamps[i];
        sum += spacings[i];
    }
    const mean = sum / @as(f64, @floatFromInt(spacings.len));

    // Search autocorrelation at lags 1..N/2 for strongest peak
    const max_lag = @min(spacings.len / 2, 512);
    var best_lag: usize = 1;
    var best_acf: f64 = -1.0;

    for (1..max_lag + 1) |lag| {
        const acf = autocorrelation(spacings, lag, mean);
        if (acf > best_acf) {
            best_acf = acf;
            best_lag = lag;
        }
    }

    // Estimated interval = mean spacing * best lag period
    // (if lag=1 has highest ACF, that means consecutive spacings are correlated,
    //  suggesting a regular interval ≈ mean spacing)
    const estimated_interval = mean * @as(f64, @floatFromInt(best_lag));

    return .{
        .interval = estimated_interval,
        .peak = @max(best_acf, 0.0),
    };
}

/// Compute jitter ratio: coefficient of variation of inter-arrival times.
/// Low jitter + high LSR = strong beacon signal.
pub fn jitterRatio(timestamps: []const f64) f64 {
    if (timestamps.len < 2) return 1.0;

    var sum: f64 = 0.0;
    const n = timestamps.len - 1;

    for (0..n) |i| {
        sum += timestamps[i + 1] - timestamps[i];
    }
    const mean = sum / @as(f64, @floatFromInt(n));
    if (mean == 0) return 1.0;

    var var_sum: f64 = 0.0;
    for (0..n) |i| {
        const d = (timestamps[i + 1] - timestamps[i]) - mean;
        var_sum += d * d;
    }
    const std_dev = @sqrt(var_sum / @as(f64, @floatFromInt(n)));

    return std_dev / mean;
}

/// Compute composite Floquet beacon score [0, 1].
///
/// Combines three signals:
///   1. LSR deviation from Poisson toward GOE (structure in timing)
///   2. Autocorrelation peak strength (periodicity) — strongest discriminator
///   3. Inverse jitter ratio (regularity)
///
/// Weights tuned against CTU-42 (Neris), CTU-46 (Virut), CTU-48 (Sogou).
/// A pure random process scores ~0. A perfect periodic beacon scores ~1.
pub fn beaconScore(lsr: f64, acf_peak: f64, jitter: f64) f64 {
    // LSR component: 0.386 (Poisson) -> 0.0, 0.530 (GOE) -> 1.0
    const lsr_norm = math.clamp((lsr - 0.386) / (0.530 - 0.386), 0.0, 1.0);

    // ACF component: direct [0,1]
    const acf_norm = math.clamp(acf_peak, 0.0, 1.0);

    // Jitter component: smooth inverse decay (no hard clip at 1.0)
    // jitter=0 -> 1.0, jitter=1 -> 0.5, jitter=3 -> 0.25
    const jitter_norm = 1.0 / (1.0 + jitter);

    // Weighted combination: ACF-heavy, tuned on 3 malware families
    return 0.30 * lsr_norm + 0.50 * acf_norm + 0.20 * jitter_norm;
}

// --- Tests ---

test "lsr: perfect periodic signal" {
    // Equal spacings should give r = 1.0 for every pair -> mean = 1.0
    const ts = [_]f64{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const r = levelSpacingRatio(&ts).?;
    try std.testing.expectApproxEqAbs(r, 1.0, 0.001);
}

test "lsr: alternating spacings" {
    // Alternating 1, 2, 1, 2... -> r = 0.5 for each pair
    const ts = [_]f64{ 0, 1, 3, 4, 6, 7, 9, 10 };
    const r = levelSpacingRatio(&ts).?;
    try std.testing.expectApproxEqAbs(r, 0.5, 0.001);
}

test "jitter: perfect periodic" {
    const ts = [_]f64{ 0, 5, 10, 15, 20, 25 };
    const j = jitterRatio(&ts);
    try std.testing.expectApproxEqAbs(j, 0.0, 0.001);
}

test "beacon score: perfect beacon" {
    const score = beaconScore(0.530, 1.0, 0.0);
    try std.testing.expectApproxEqAbs(score, 1.0, 0.001);
}

test "beacon score: random traffic" {
    // jitter=1 -> jitter_norm = 0.5, so score = 0.30*0 + 0.50*0 + 0.20*0.5 = 0.1
    const score = beaconScore(0.386, 0.0, 1.0);
    try std.testing.expectApproxEqAbs(score, 0.1, 0.001);
}
