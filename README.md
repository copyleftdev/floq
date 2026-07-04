# floq

A C2 beacon detector built on Floquet spectral analysis — the physics of finding periodic signals hidden in chaos.

**274KB static binary. Reads pcap, live capture, or OpenTelemetry JSONL. Finds needles in chaos.**

## Why this exists

Every beacon detection tool in the security industry uses the same approach: standard deviation and coefficient of variation on connection intervals. RITA, Flare, BeaconHunter — they all compute `stddev / mean` and call it a day. This works for textbook beacons with low jitter, but real C2 traffic is bursty, jittered, and buried in noise. A 15% jitter Cobalt Strike beacon mixed into a busy network looks like random traffic to a stddev-based detector.

We looked at this problem and asked: who else detects hidden periodic signals in noisy data?

Physicists. Specifically, quantum chaos researchers.

Nobody had built this bridge from physics to security. So we researched it, tested it against real malware, stress-tested it against synthetic chaos, and shipped it.

## The name

**Floquet** (flo-KAY) — from Gaston Floquet's mathematical framework for analyzing periodic systems. Floquet theory says: any system driven by a periodic force, no matter how complex or noisy, has a fundamental periodic structure that can be decomposed and identified. The Floquet operator captures what happens over exactly one period. The quasi-energies reveal hidden periodicities even when the raw signal looks chaotic.

This is exactly what `floq` does to network traffic. C2 beacons are periodic drivers. Network noise is the complex system. Floquet analysis decomposes the chaos and finds the period.

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
| CTU-42 (Neris) | Kelihos P2P botnet | UDP beacon ~180s | **Top hit: score 0.816, period_sig 1.00** — primary C2 server is the *only* alert at t=0.6 |
| CTU-48 (Sogou) | Chinese IRC malware | IRC persistent conn | **0 detections** — correct, IRC doesn't beacon |
| CTU-46 (Virut) | Fast-flux IRC botnet | IRC + clickfraud | **0 detections** — correct, IRC doesn't beacon |

### Chaos needle test

40,000+ packets of synthetic chaos (Poisson bursts, TCP floods, port scans, DNS storms, exponential backoff retries, drifting heartbeats, chatty microservices) with 5 beacons hidden inside at varying intervals and jitter levels.

```
Chaos Needle Test — 5 seeds, threshold=0.5
══════════════════════════════════════════════
  Needles found:     25/25 (100%)
  Score range:       [0.569 - 0.718]
  Avg false positives per seed:  2.2

  ALL SEEDS PASSED
══════════════════════════════════════════════
```

The hardest needle — 300-second interval, 25% jitter, only 26 packets in a 2-hour capture — was found in every single run. The remaining false positives are the synthetic "drifting heartbeat" flows (monitoring agents with slow interval drift), which score just over threshold at 0.50–0.52 — genuinely beacon-adjacent traffic that sits below every real needle. The previous ACF-based scoring reported ~32 false positives per seed at this threshold; null-calibrating the periodicity term and penalizing overdispersion cut that by an order of magnitude while keeping 100% recall.

## Install

Requires [Zig](https://ziglang.org/download/) >= 0.14.0 and libpcap-dev.

```bash
sudo apt install libpcap-dev    # Debian/Ubuntu

git clone https://github.com/YOURUSER/floq.git
cd floq
zig build -Doptimize=ReleaseSafe

# Binary at zig-out/bin/floq (274KB)
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
alerts:    19
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
floq (274KB)
├── main.zig        Event loop, CLI, signal handling, stats
├── capture.zig     libpcap: Ethernet/VLAN/IPv4/IPv6 parsing
├── ingest.zig      JSONL stdin reader with OTel support
├── detector.zig    Per-flow state, sliding window, LRU eviction
├── spectral.zig    LSR, autocorrelation, jitter, Floquet scoring
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
