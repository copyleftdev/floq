#!/usr/bin/env python3
"""Generate JSONL test data with known beacon patterns."""
import json, random

random.seed(42)
events = []

# Beacon: 60s interval, 5% jitter — should be detected
for i in range(30):
    jitter = 60 * 0.05 * (random.random() * 2 - 1)
    events.append({
        "ts": 1000 + i * 60 + jitter,
        "src": "10.0.0.50",
        "dst": "203.0.113.100",
        "port": 443,
        "proto": "tcp"
    })

# OTel format beacon: 30s interval — should be detected
for i in range(40):
    jitter = 30 * 0.10 * (random.random() * 2 - 1)
    ns = int((1000 + i * 30 + jitter) * 1_000_000_000)
    events.append({
        "startTimeUnixNano": str(ns),
        "client.address": "10.0.0.51",
        "server.address": "198.51.100.200",
        "server.port": 8080
    })

# Random traffic — should NOT be detected
for _ in range(50):
    events.append({
        "ts": 1000 + random.random() * 1800,
        "src": "10.0.0.100",
        "dst": "93.184.216.34",
        "port": 443,
        "proto": "tcp"
    })

# NTP (should be filtered by allowlist)
for i in range(20):
    events.append({
        "ts": 1000 + i * 64,
        "src": "10.0.0.1",
        "dst": "10.0.0.2",
        "port": 123,
        "proto": "udp"
    })

events.sort(key=lambda e: e.get("ts", int(e.get("startTimeUnixNano", "0")) / 1e9))

with open("test-beacon.jsonl", "w") as f:
    for e in events:
        f.write(json.dumps(e) + "\n")

print(f"Generated test-beacon.jsonl: {len(events)} events")
print("  Beacon 60s TCP:443 (simple format) — 30 events")
print("  Beacon 30s TCP:8080 (OTel format) — 40 events")
print("  Random TCP:443 — 50 events")
print("  NTP :123/udp (allowlisted) — 20 events")
