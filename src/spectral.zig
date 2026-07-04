const std = @import("std");
const math = std.math;

/// Compute the level spacing ratio (LSR) from a sorted sequence of timestamps.
///
/// Given inter-arrival times s_i = t_{i+1} - t_i, compute:
///   r_i = min(s_i, s_{i+1}) / max(s_i, s_{i+1})
///
/// Mean r = 2ln2-1 ≈ 0.386 for Poisson (random/no structure)
/// Mean r -> 1.0 for a regular "picket fence" (periodic — beacon-like);
/// jitter pulls it back toward the Poisson value.
///
/// The r-statistic is scale-invariant and purely local (consecutive pairs),
/// so it is robust to slow interval drift, unlike a global CV.
/// Diagnostic from random matrix theory: Oganesyan & Huse (2007), Atas et al. (2013).
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

/// Detect statistically significant structure in the spacing sequence.
/// Returns (estimated_interval, significance in [0,1]).
///
/// A beacon with independent per-sleep jitter produces i.i.d. spacings, whose
/// population ACF is zero at every lag — so a raw ACF maximum is just the max
/// of ~L noisy estimates and rewards small samples. Instead, the best peak is
/// compared against its null distribution: for structureless spacings the
/// sample ACF at one lag is ~N(0, 1/m), so the max over L lags concentrates
/// near sqrt(2 ln L / m). Only the excess above that noise floor counts as
/// evidence, which makes the significance grow with sample count instead of
/// shrinking.
pub fn detectPeriodicity(timestamps: []const f64) struct { interval: f64, significance: f64 } {
    if (timestamps.len < 4) return .{ .interval = 0, .significance = 0 };

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

    // Null-calibrated significance: z-score of the peak minus the expected
    // max-of-noise, scaled so ~3 sigma of excess earns full credit.
    const m = @as(f64, @floatFromInt(spacings.len));
    const z = best_acf * @sqrt(m);
    const z_null = @sqrt(2.0 * @log(@as(f64, @floatFromInt(@max(max_lag, 2)))));
    const sig = math.clamp((z - z_null) / 3.0, 0.0, 1.0);

    // A significant peak at lag L means the spacing sequence repeats every L
    // steps, so the flow's periodic block is L * mean. Without a significant
    // peak, the best interval estimate is simply the mean spacing.
    const estimated_interval = if (sig > 0)
        mean * @as(f64, @floatFromInt(best_lag))
    else
        mean;

    return .{
        .interval = estimated_interval,
        .significance = sig,
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

/// Compute composite beacon score [0, 1].
///
/// Combines three signals and one penalty:
///   1. LSR regularity: Poisson baseline (2ln2-1 ≈ 0.386) -> 0, perfectly
///      regular "picket fence" spacings (r = 1) -> 1. Local pairwise ratios
///      make this robust to slow interval drift, unlike a global CV.
///   2. Spacing-structure significance (null-calibrated, see detectPeriodicity)
///   3. Inverse jitter ratio (regularity)
///   4. Overdispersion penalty: CV > 1 is super-Poisson (bursts, backoff
///      retries) — more irregular than random, which no periodic beacon is.
///
/// A pure random process scores ~0.15. A perfect periodic beacon scores ~1.
pub fn beaconScore(lsr: f64, period_sig: f64, jitter: f64) f64 {
    // LSR component: 0.386 (Poisson) -> 0.0, 1.0 (clean beacon) -> 1.0
    const lsr_norm = math.clamp((lsr - 0.386) / (1.0 - 0.386), 0.0, 1.0);

    // Structure component: already a calibrated [0,1] significance
    const sig_norm = math.clamp(period_sig, 0.0, 1.0);

    // Jitter component: smooth inverse decay (no hard clip at 1.0)
    // jitter=0 -> 1.0, jitter=1 -> 0.5, jitter=3 -> 0.25
    const jitter_norm = 1.0 / (1.0 + jitter);

    // Overdispersion penalty: 0 at CV <= 1, full at CV >= 3
    const burst_pen = math.clamp((jitter - 1.0) / 2.0, 0.0, 1.0);

    const score = 0.45 * lsr_norm + 0.25 * sig_norm + 0.30 * jitter_norm - 0.20 * burst_pen;
    return math.clamp(score, 0.0, 1.0);
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
    const score = beaconScore(1.0, 1.0, 0.0);
    try std.testing.expectApproxEqAbs(score, 1.0, 0.001);
}

test "beacon score: random traffic" {
    // jitter=1 -> jitter_norm = 0.5, so score = 0.45*0 + 0.25*0 + 0.30*0.5 = 0.15
    const score = beaconScore(0.386, 0.0, 1.0);
    try std.testing.expectApproxEqAbs(score, 0.15, 0.001);
}

test "beacon score: bursty overdispersion is penalized" {
    // High LSR but CV=3 (bursts + long gaps): penalty must keep it below alert range
    const score = beaconScore(0.85, 0.0, 3.0);
    try std.testing.expect(score < 0.3);
}

test "periodicity: significance grows with evidence" {
    var short: [11]f64 = undefined;
    for (0..short.len) |i| short[i] = @as(f64, @floatFromInt(i)) * 60.0;
    var long: [51]f64 = undefined;
    for (0..long.len) |i| long[i] = @as(f64, @floatFromInt(i)) * 60.0;

    const p_short = detectPeriodicity(&short);
    const p_long = detectPeriodicity(&long);

    try std.testing.expect(p_short.significance > 0);
    try std.testing.expect(p_long.significance > p_short.significance);
    try std.testing.expectApproxEqAbs(p_short.interval, 60.0, 0.001);
    try std.testing.expectApproxEqAbs(p_long.interval, 60.0, 0.001);
}

test "periodicity: jittered beacon has no spurious peak" {
    // 15% jitter via LCG: i.i.d. spacings have no real ACF structure, so the
    // significance must be zero and the interval must fall back to the mean.
    var ts: [40]f64 = undefined;
    var t: f64 = 0;
    var state: u64 = 12345;
    for (0..ts.len) |i| {
        ts[i] = t;
        state = state *% 6364136223846793005 +% 1442695040888963407;
        const u = @as(f64, @floatFromInt(state >> 11)) / @as(f64, @floatFromInt(@as(u64, 1) << 53));
        t += 60.0 * (1.0 + 0.15 * (2.0 * u - 1.0));
    }

    const p = detectPeriodicity(&ts);
    try std.testing.expectApproxEqAbs(p.significance, 0.0, 0.001);
    try std.testing.expect(@abs(p.interval - 60.0) < 60.0 * 0.1);
}
