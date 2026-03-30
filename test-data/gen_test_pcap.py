#!/usr/bin/env python3
"""Generate test pcap files with known C2 beacon patterns + normal traffic."""

import random
import struct
from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap

random.seed(42)


def gen_beacon_flow(
    src_ip, dst_ip, dst_port, interval, jitter_pct, duration, start_time=0
):
    """Generate periodic beacon packets with controllable jitter."""
    packets = []
    t = start_time
    while t < start_time + duration:
        jitter = interval * jitter_pct * (random.random() * 2 - 1)
        pkt = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="PA")
            / Raw(load=b"GET /pixel.gif HTTP/1.1\r\nHost: update-service.com\r\n\r\n")
        )
        pkt.time = t
        packets.append(pkt)
        t += interval + jitter
    return packets


def gen_normal_traffic(src_ip, dst_ip, dst_port, n_packets, start_time=0, duration=3600):
    """Generate random (Poisson-distributed) normal traffic."""
    packets = []
    times = sorted([start_time + random.random() * duration for _ in range(n_packets)])
    for t in times:
        pkt = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="PA")
            / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: legit-site.com\r\n\r\n")
        )
        pkt.time = t
        packets.append(pkt)
    return packets


def gen_dns_beacon(src_ip, dst_ip, interval, jitter_pct, duration, start_time=0):
    """Generate DNS-based C2 beacon (subdomain encoding)."""
    packets = []
    t = start_time
    seq = 0
    while t < start_time + duration:
        jitter = interval * jitter_pct * (random.random() * 2 - 1)
        subdomain = f"{seq:06x}.beacon.evil.com"
        pkt = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / Raw(load=subdomain.encode())
        )
        pkt.time = t
        packets.append(pkt)
        t += interval + jitter
        seq += 1
    return packets


all_packets = []
duration = 3600  # 1 hour

# === BEACON FLOWS (should be detected) ===

# 1. Classic Cobalt Strike: 60s interval, 0% jitter (textbook)
all_packets += gen_beacon_flow(
    "10.0.0.50", "203.0.113.100", 443, interval=60, jitter_pct=0.0,
    duration=duration, start_time=0
)

# 2. Cobalt Strike with 10% jitter (common real-world config)
all_packets += gen_beacon_flow(
    "10.0.0.51", "198.51.100.200", 8443, interval=60, jitter_pct=0.10,
    duration=duration, start_time=0
)

# 3. Slow beacon: 5 minute interval, 20% jitter (evasive)
all_packets += gen_beacon_flow(
    "10.0.0.52", "192.0.2.50", 80, interval=300, jitter_pct=0.20,
    duration=duration, start_time=0
)

# 4. Fast beacon: 10s interval, 5% jitter (aggressive C2)
all_packets += gen_beacon_flow(
    "10.0.0.53", "203.0.113.200", 8080, interval=10, jitter_pct=0.05,
    duration=duration, start_time=0
)

# 5. DNS beacon: 30s interval, 15% jitter
all_packets += gen_dns_beacon(
    "10.0.0.54", "8.8.8.8", interval=30, jitter_pct=0.15,
    duration=duration, start_time=0
)

# === NORMAL FLOWS (should NOT be detected) ===

# 6. Bursty web browsing
all_packets += gen_normal_traffic(
    "10.0.0.100", "93.184.216.34", 443, n_packets=200, duration=duration
)

# 7. Another normal user
all_packets += gen_normal_traffic(
    "10.0.0.101", "151.101.1.140", 443, n_packets=150, duration=duration
)

# 8. Sparse DNS queries (random)
all_packets += gen_normal_traffic(
    "10.0.0.102", "8.8.4.4", 53, n_packets=80, duration=duration
)

# Sort all packets by timestamp
all_packets.sort(key=lambda p: p.time)

outfile = "test-beacon-mix.pcap"
wrpcap(outfile, all_packets)

# Print summary
beacon_count = sum(1 for p in all_packets if p[IP].src.startswith("10.0.0.5"))
normal_count = sum(1 for p in all_packets if p[IP].src.startswith("10.0.0.1"))
print(f"Generated {outfile}:")
print(f"  Total packets: {len(all_packets)}")
print(f"  Beacon flows:  {beacon_count} packets (5 flows)")
print(f"  Normal flows:  {normal_count} packets (3 flows)")
print()
print("Expected detections:")
print("  10.0.0.50 -> 203.0.113.100:443/tcp   60s  0% jitter  (easy)")
print("  10.0.0.51 -> 198.51.100.200:8443/tcp  60s 10% jitter  (medium)")
print("  10.0.0.52 -> 192.0.2.50:80/tcp       300s 20% jitter  (hard)")
print("  10.0.0.53 -> 203.0.113.200:8080/tcp   10s  5% jitter  (easy)")
print("  10.0.0.54 -> 8.8.8.8:53/udp           30s 15% jitter  (medium)")
print()
print("Expected non-detections:")
print("  10.0.0.100 -> 93.184.216.34:443/tcp   random")
print("  10.0.0.101 -> 151.101.1.140:443/tcp   random")
print("  10.0.0.102 -> 8.8.4.4:53/tcp          random")
