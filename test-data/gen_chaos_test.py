#!/usr/bin/env python3
"""
Chaos Needle Test Generator

Generates a pcap with massive chaotic background noise and specific
"needle" beacons hidden inside. The test MUST always find the needles
regardless of how much chaos surrounds them.

Chaos types:
  - Poisson random bursts (web browsing, API calls)
  - Bursty TCP floods (file transfers, streaming)
  - Periodic-looking-but-not (heartbeats with drift)
  - Multi-modal traffic (mix of fast and slow)
  - Port-scanning noise
  - DNS query storms
  - Connection resets / retries with exponential backoff

Needles (MUST be detected):
  1. Slow beacon: 300s interval, 25% jitter — hardest to find
  2. Medium beacon: 60s interval, 15% jitter — standard C2
  3. Fast beacon: 10s interval, 10% jitter — aggressive C2
  4. Jittered DNS beacon: 45s interval, 30% jitter — DNS C2
  5. Micro-beacon: 5s interval, 5% jitter buried in flood traffic
"""

import random
import json
import sys
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

random.seed(int(sys.argv[1]) if len(sys.argv) > 1 else 42)

DURATION = 7200  # 2 hours
VICTIM = "10.1.1.100"
all_packets = []


def pkt(src, dst, dport, proto="tcp", t=0):
    sport = random.randint(1024, 65535)
    if proto == "tcp":
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=b"X" * 20)
    else:
        p = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=b"X" * 20)
    p.time = t
    return p


# ============================================================
# NEEDLES — these MUST be detected
# ============================================================
needles = {}

def add_needle(name, src, dst, dport, proto, interval, jitter_pct):
    """Generate a beacon flow and register it as a needle."""
    packets = []
    t = random.uniform(0, 300)  # random start offset to hide in the noise
    while t < DURATION:
        jitter = interval * jitter_pct * (random.random() * 2 - 1)
        packets.append(pkt(src, dst, dport, proto, t))
        t += interval + jitter
    needles[f"{src}->{dst}:{dport}/{proto}"] = {
        "name": name,
        "interval": interval,
        "jitter_pct": jitter_pct,
        "count": len(packets),
    }
    return packets

# Needle 1: Slow beacon (hardest — low sample count, high jitter)
all_packets += add_needle(
    "slow_beacon", "172.16.5.99", "203.0.113.50", 443, "tcp",
    interval=300, jitter_pct=0.25
)

# Needle 2: Medium beacon (classic Cobalt Strike profile)
all_packets += add_needle(
    "medium_beacon", "172.16.5.100", "198.51.100.77", 8443, "tcp",
    interval=60, jitter_pct=0.15
)

# Needle 3: Fast beacon (aggressive C2)
all_packets += add_needle(
    "fast_beacon", "172.16.5.101", "192.0.2.200", 8080, "tcp",
    interval=10, jitter_pct=0.10
)

# Needle 4: DNS beacon (subdomain C2 over DNS)
all_packets += add_needle(
    "dns_beacon", "172.16.5.102", "198.51.100.53", 53, "udp",
    interval=45, jitter_pct=0.30
)

# Needle 5: Micro-beacon buried in flood traffic from same subnet
all_packets += add_needle(
    "micro_beacon", "172.16.5.103", "203.0.113.99", 443, "tcp",
    interval=5, jitter_pct=0.05
)


# ============================================================
# CHAOS — massive background noise
# ============================================================

def random_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# --- Type 1: Poisson random web traffic (many sources) ---
for _ in range(80):
    src = f"10.1.1.{random.randint(1, 254)}"
    dst = random_ip()
    port = random.choice([80, 443, 8080, 8443])
    n = random.randint(20, 200)
    times = sorted([random.uniform(0, DURATION) for _ in range(n)])
    for t in times:
        all_packets.append(pkt(src, dst, port, "tcp", t))

# --- Type 2: Bursty TCP floods (file transfers) ---
for _ in range(30):
    src = f"10.1.1.{random.randint(1, 254)}"
    dst = random_ip()
    port = random.choice([22, 443, 3389, 445])
    # 2-5 bursts of 50-200 packets each
    for _ in range(random.randint(2, 5)):
        burst_start = random.uniform(0, DURATION)
        burst_len = random.uniform(0.5, 10)
        n = random.randint(50, 200)
        for j in range(n):
            t = burst_start + (j / n) * burst_len + random.uniform(-0.01, 0.01)
            all_packets.append(pkt(src, dst, port, "tcp", t))

# --- Type 3: Periodic-looking but with drift (NTP, monitoring) ---
for _ in range(15):
    src = f"10.1.1.{random.randint(1, 254)}"
    dst = random_ip()
    port = random.choice([161, 5000, 9090, 3000])
    interval = random.uniform(30, 120)
    t = 0
    drift = random.uniform(-0.005, 0.005)  # cumulative drift
    while t < DURATION:
        all_packets.append(pkt(src, dst, port, "tcp", t))
        interval += drift  # interval slowly changes
        jitter = interval * random.uniform(0.3, 0.7) * (random.random() * 2 - 1)
        t += interval + jitter

# --- Type 4: Port scanning noise ---
for _ in range(10):
    src = random_ip()
    for port in random.sample(range(1, 65535), random.randint(100, 500)):
        t = random.uniform(0, DURATION)
        all_packets.append(pkt(src, VICTIM, port, "tcp", t))

# --- Type 5: DNS query storms ---
for _ in range(20):
    src = f"10.1.1.{random.randint(1, 254)}"
    dns_server = random.choice(["10.1.1.1", "10.1.1.2"])
    n = random.randint(50, 300)
    times = sorted([random.uniform(0, DURATION) for _ in range(n)])
    for t in times:
        all_packets.append(pkt(src, dns_server, 53, "udp", t))

# --- Type 6: Exponential backoff retries (connection failures) ---
for _ in range(20):
    src = f"10.1.1.{random.randint(1, 254)}"
    dst = random_ip()
    port = random.choice([443, 5432, 6379, 27017])
    t = random.uniform(0, DURATION)
    for attempt in range(random.randint(5, 15)):
        all_packets.append(pkt(src, dst, port, "tcp", t))
        t += (2 ** attempt) * random.uniform(0.8, 1.2)
        if t > DURATION:
            break

# --- Type 7: Chatty microservices (same subnet, high frequency) ---
for _ in range(25):
    src = f"172.16.5.{random.randint(1, 254)}"
    dst = f"172.16.5.{random.randint(1, 254)}"
    if src == dst:
        continue
    port = random.choice([8080, 8443, 9090, 3000, 5000])
    n = random.randint(100, 500)
    times = sorted([random.uniform(0, DURATION) for _ in range(n)])
    for t in times:
        all_packets.append(pkt(src, dst, port, "tcp", t))

# --- Type 8: Background ICMP (pings, traceroutes) ---
for _ in range(10):
    src = f"10.1.1.{random.randint(1, 254)}"
    dst = random_ip()
    n = random.randint(10, 50)
    times = sorted([random.uniform(0, DURATION) for _ in range(n)])
    for t in times:
        p = Ether() / IP(src=src, dst=dst) / UDP(sport=0, dport=0) / Raw(load=b"\x08\x00")
        p.time = t
        all_packets.append(p)


# ============================================================
# Sort and write
# ============================================================
all_packets.sort(key=lambda p: p.time)

outfile = "chaos-needle-test.pcap"
wrpcap(outfile, all_packets)

# Write needle manifest for test validation
manifest = {
    "description": "Chaos needle test — find beacons buried in noise",
    "duration_secs": DURATION,
    "total_packets": len(all_packets),
    "needle_count": len(needles),
    "needles": needles,
}

with open("chaos-needle-manifest.json", "w") as f:
    json.dump(manifest, f, indent=2)

# Summary
noise_count = len(all_packets) - sum(n["count"] for n in needles.values())
needle_total = sum(n["count"] for n in needles.values())

print(f"Generated {outfile}:")
print(f"  Total packets:  {len(all_packets):,}")
print(f"  Noise packets:  {noise_count:,} ({100*noise_count/len(all_packets):.1f}%)")
print(f"  Needle packets: {needle_total:,} ({100*needle_total/len(all_packets):.1f}%)")
print(f"  Seed: {int(sys.argv[1]) if len(sys.argv) > 1 else 42}")
print()
print("Needles:")
for key, info in needles.items():
    print(f"  {info['name']:<16} {key:<50} {info['interval']:>5.0f}s ±{info['jitter_pct']*100:.0f}%  ({info['count']} pkts)")
