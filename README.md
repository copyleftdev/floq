# floq

A C2 beacon detector that borrows the spectral statistics quantum-chaos physicists use to tell structured signals from noise — applied to network flow timing.

**276KB static binary. Reads pcap, live capture, or OpenTelemetry JSONL. Finds needles in chaos.**

## Why this exists

Most beacon detection tools use one signal: standard deviation and coefficient of variation on connection intervals. RITA, Flare, BeaconHunter — they compute `stddev / mean` and threshold it. That works for textbook beacons with low jitter, but real C2 traffic is bursty, jittered, and buried in noise. A 15%-jitter Cobalt Strike beacon in a busy network looks a lot like ordinary traffic to a CV-only detector, and long-interval drift degrades CV even for clean beacons.

The question `floq` starts from: who else has to separate a faint periodic signal from a noisy background? Physicists — specifically the random-matrix-theory diagnostics from quantum chaos, which classify a sequence of levels as *random* or *structured* from the statistics of their spacings alone. The **level spacing ratio** turns out to be a well-behaved, scale-invariant, drift-robust regularity measure for network timing, and it does most of the work here. `floq` pairs it with a coefficient-of-variation term and a null-calibrated periodicity check, then combines the three.

## The name

**Floquet** (flo-KAY) — Gaston Floquet's framework for periodically driven systems, where a hidden fundamental period survives even in complex, noisy dynamics. It's the inspiration for the periodicity component and a fitting name for a beacon finder. To be precise about what the tool actually computes: `floq` does *not* build a Floquet operator or diagonalize a quasi-energy spectrum. It computes classical spectral and time-series statistics on inter-arrival timing (see [How it works](#how-it-works) and [The science](#the-science)). The physics is where the ideas come from, not a literal simulation running under the hood.

## How it works

`floq` computes three spectral diagnostics on each network flow's timing:

| Metric | Origin | What it measures |
|---|---|---|
| **LSR** (Level Spacing Ratio) | Random matrix theory | Local regularity of consecutive inter-arrival times: Poisson traffic sits at r ≈ 0.386, a clean beacon approaches r = 1. Scale-invariant and robust to slow interval drift |
| **Period significance** | Extreme-value-calibrated autocorrelation | Whether the spacing *sequence* has statistically real structure (repeating patterns, burst cycles) — the ACF peak is credited only above its max-of-noise floor, so evidence grows with sample count |
| **Jitter** (Coefficient of Variation) | Classical statistics | How regular the timing is — lower = more beacon-like. CV > 1 (super-Poisson) is penalized: bursts and backoff retries are *more* irregular than random, which no periodic beacon is |

These are combined into a composite score (0-1):

```
score = 0.45 * LSR_norm + 0.25 * period_sig + 0.30 / (1 + CV) - 0.20 * overdispersion_penalty
```

LSR and CV carry most of the discrimination — a beacon with independent per-sleep jitter (how Cobalt Strike works) produces i.i.d. spacings, so all of its signal lives in the spacing distribution, and a raw autocorrelation peak is mathematically incapable of adding evidence for it. The significance term exists for flows whose spacing sequence has *real* structure (e.g. the Neris C2's burst pattern scores 1.0), calibrated against the `sqrt(2 ln L / m)` noise floor so it never rewards small samples. The jitter term uses smooth inverse decay (`1/(1+CV)`), and the overdispersion penalty removes flood/burst/backoff flows that regularity metrics alone would misread.

## Validation

### Real malware (CTU datasets)

| Dataset | Malware | C2 Type | Result |
|---|---|---|---|
| CTU-42 (Neris) | Neris botnet | UDP beacon ~180s | **Top hit: score 0.816, period_sig 1.00** — primary C2 server is the *only* flow alerted at t=0.6 |
| CTU-46 (Virut) | Virut | IRC C2 + fast-flux, spam | **0 detections** — correct, no fixed-interval beacon |
| CTU-48 (Sogou) | Sogou | IRC + HTTP + DNS, spam/clickfraud | **0 detections** — correct, no fixed-interval beacon |

### Chaos needle test

40,000+ packets of synthetic chaos (Poisson bursts, TCP floods, port scans, DNS storms, exponential backoff retries, drifting heartbeats, chatty microservices) with 5 beacons hidden inside at varying intervals and jitter levels.

```
Chaos Needle Test — 10 seeds, threshold=0.5
══════════════════════════════════════════════
  Needles found:     50/50 (100%)
  Score range:       [0.562 - 0.718]
  Avg false positives per seed:  1.9

  ALL SEEDS PASSED
══════════════════════════════════════════════
```

The hardest needle — 300-second interval, 25% jitter, only 26 packets in a 2-hour capture — was found in every single run. The remaining false positives are the synthetic "drifting heartbeat" flows (monitoring agents with slow interval drift), which land just over threshold at 0.50–0.52 — genuinely beacon-adjacent traffic that sits below every real needle. The previous ACF-based scoring produced roughly 30 false positives per seed at this threshold; null-calibrating the periodicity term and penalizing overdispersion cut that by an order of magnitude while keeping 100% recall.

## Install

Requires [Zig](https://ziglang.org/download/) >= 0.14.0 and libpcap-dev.

```bash
sudo apt install libpcap-dev    # Debian/Ubuntu

git clone https://github.com/copyleftdev/floq.git
cd floq
zig build -Doptimize=ReleaseSafe

# Binary at zig-out/bin/floq (~276KB)
```

### Verify

```bash
zig build test

# Chaos needle test (requires Python 3 + scapy)
pip install scapy
cd test-data && python3 run_chaos_test.py --seeds 5
```

## Usage

```bash
# Live capture
sudo floq -i eth0 -f "tcp" -t 0.5

# Read pcap file
floq -r capture.pcap --json

# Pipe from tcpdump
sudo tcpdump -i eth0 -w - | floq -r - -t 0.5

# OpenTelemetry JSONL from stdin
cat flows.jsonl | floq --stdin --json

# With custom allowlist
floq -r capture.pcap --allowlist internal-services.txt
```

### Output

```
[FLOQ] score=0.816  95.211.58.97 -> 147.32.84.165:1293/udp  interval=199.6s  jitter=0.450  lsr=0.876  period_sig=1.000  n=84
```

JSON (`--json`) and CSV (`--csv`) output modes available. Stats printed to stderr on exit:

```
--- floq stats ---
duration:  1s
packets:   322248 processed, 906 skipped
flows:     9004 active
alerts:    2
```

### Options

```
INPUT MODES:
  -i <iface>         Live capture on interface (requires root)
  -r <file>          Read from pcap file
  --stdin            Read JSONL connection events from stdin

OPTIONS:
  -f <filter>        BPF filter expression (e.g. "tcp")
  -w <seconds>       Sliding window duration (default: 300)
  -t <0.0-1.0>       Beacon score threshold (default: 0.6)
  -n <count>         Minimum samples per flow (default: 10)
  -a <seconds>       Analysis interval (default: 30)
  --max-flows <N>    Maximum tracked flows (default: 100000)
  --json             JSON output (one object per line)
  --csv              CSV output
  --allowlist <file> Load additional allowlist entries from file
  --no-allowlist     Disable built-in allowlist (NTP, SNMP, etc.)
  -v, --verbose      Periodic stats to stderr
  -V, --version      Show version and exit
```

### JSONL format (--stdin)

```json
{"ts":1234567890.5,"src":"10.0.0.1","dst":"203.0.113.50","port":443,"proto":"tcp"}
```

OpenTelemetry semantic conventions supported:

```json
{"startTimeUnixNano":"1234567890000000000","client.address":"10.0.0.1","server.address":"203.0.113.50","server.port":443}
```

IPv6 works in both pcap and JSONL modes:

```json
{"ts":1234.5,"src":"2001:db8::1","dst":"::ffff:5.6.7.8","port":80,"proto":"tcp"}
```

### Allowlist file format

```
# Known periodic services (one per line)
123/udp           # NTP
161/udp           # SNMP
10.1.1.1:53/udp   # Internal DNS resolver
```

## Architecture

```
floq (~276KB)
├── main.zig        Event loop, CLI, signal handling, stats
├── capture.zig     libpcap: Ethernet/VLAN/IPv4/IPv6 parsing
├── ingest.zig      JSONL stdin reader with OTel support
├── detector.zig    Per-flow state, sliding window, LRU eviction
├── spectral.zig    Level spacing ratio, jitter, periodicity significance, composite score
├── allowlist.zig   Built-in + file-based allowlists
├── output.zig      Human/JSON/CSV formatters, exit stats
└── types.zig       FlowKey ([16]u8 addrs), Config
```

### Production features

- **IPv4 + IPv6** with unified `[16]u8` address representation
- **802.1Q + QinQ VLAN tag stripping**
- **Linux SLL** (cooked capture) link type support
- **Flow count cap** (default 100K) with LRU eviction
- **SIGINT/SIGTERM** graceful shutdown with final analysis pass
- **128-byte snaplen** — captures only L4 headers

## The science

The level spacing ratio comes from random matrix theory, where it classifies spectra by the statistics of consecutive spacings. Two anchors matter here:

- **Poisson** (r = 2ln2−1 ≈ 0.386): spacings are uncorrelated exponentials — genuinely random arrivals
- **Picket fence** (r → 1): spacings are all equal — a periodic driver

Network connection timestamps from random user activity follow Poisson statistics and sit at the 0.386 anchor. A periodic C2 beacon sits near the picket-fence limit, and jitter pulls it back toward Poisson: a 15%-jitter beacon measures r ≈ 0.91, a 50%-jitter beacon r ≈ 0.73. `floq` scores the distance from the Poisson null toward the picket-fence limit. (The GOE value 0.5307 familiar from quantum chaos sits between the two anchors, but beacons are picket-fence-class, not GOE — periodic timing is regular, not level-repelling.)

Two properties make the r-statistic well suited to C2 detection. It is invariant to the absolute scale of intervals — a beacon at 10-second and one at 300-second intervals produce the same r for the same jitter profile. And it is purely local (ratios of *consecutive* spacings), so a beacon whose interval drifts over hours keeps a high r while its global CV degrades.

The period-significance component is classical time-series analysis with extreme-value calibration. A subtle point drives the design: a beacon with independent per-sleep jitter produces i.i.d. spacings, whose autocorrelation is zero at every lag — the periodicity of the *events* leaves no trace in the ACF of the *spacings*. A raw ACF peak is therefore just the maximum of many noise estimates (which concentrates at `sqrt(2 ln L / m)` and *shrinks* with more data). `floq` subtracts that noise floor and credits only the statistically significant excess — real repeating structure in the spacing sequence, like the burst cycles of the Neris C2 protocol.

### References

1. Oganesyan, V. & Huse, D. (2007). *Localization of interacting fermions at high temperature*. Phys. Rev. B — introduced the level spacing ratio diagnostic.
2. Atas, Y.Y. et al. (2013). *Distribution of the ratio of consecutive level spacings in random matrix ensembles*. Phys. Rev. Lett. — the Poisson value 2ln2−1 used as the null anchor.

## Testing

```bash
# Unit tests
zig build test

# Chaos needle test — 40K packets of noise with 5 hidden beacons
cd test-data && python3 run_chaos_test.py --seeds 10

# Test against real malware (download CTU datasets)
wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap -P test-data/
floq -r test-data/botnet-capture-20110810-neris.pcap -t 0.6 -n 10 -w 25000 -a 9999 --json
```

## License

MIT
