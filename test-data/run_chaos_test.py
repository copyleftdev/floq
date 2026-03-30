#!/usr/bin/env python3
"""
Chaos Needle Test Runner

Generates chaotic traffic with hidden beacons using multiple random seeds,
runs beacon against each, and asserts ALL needles are ALWAYS found.

Usage:
  python3 run_chaos_test.py [--seeds N] [--threshold T]

Exit code 0 = all seeds passed, 1 = at least one failure.
"""

import subprocess
import json
import sys
import os
import argparse

BEACON_BIN = os.path.join(os.path.dirname(__file__), "..", "zig-out", "bin", "floq")
GEN_SCRIPT = os.path.join(os.path.dirname(__file__), "gen_chaos_test.py")
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def generate(seed):
    """Generate chaos pcap with given seed."""
    result = subprocess.run(
        ["python3", GEN_SCRIPT, str(seed)],
        cwd=TEST_DIR,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  FAIL: pcap generation failed: {result.stderr}", file=sys.stderr)
        return False
    return True


def run_beacon(threshold):
    """Run beacon on the chaos pcap and return detected flows."""
    pcap = os.path.join(TEST_DIR, "chaos-needle-test.pcap")
    result = subprocess.run(
        [BEACON_BIN, "-r", pcap, "-t", str(threshold),
         "-n", "10", "-w", "7200", "-a", "9999", "--no-allowlist", "--json"],
        capture_output=True, text=True
    )
    flows = {}
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        r = json.loads(line)
        key = f"{r['src']}->{r['dst']}:{r['port']}/{r['proto']}"
        if key not in flows or r["score"] > flows[key]["score"]:
            flows[key] = r
    return flows


def check_needles(detected, manifest):
    """Check if all needles were found. Returns (found, missing, fps)."""
    needle_keys = set(manifest["needles"].keys())
    found = {}
    fps = {}

    for key, r in detected.items():
        if key in needle_keys:
            found[key] = r
        else:
            fps[key] = r

    missing = needle_keys - set(found.keys())
    return found, missing, fps


def run_seed(seed, threshold):
    """Run full test for one seed. Returns (passed, stats)."""
    if not generate(seed):
        return False, {}

    with open(os.path.join(TEST_DIR, "chaos-needle-manifest.json")) as f:
        manifest = json.load(f)

    detected = run_beacon(threshold)
    found, missing, fps = check_needles(detected, manifest)

    needle_scores = [found[k]["score"] for k in found] if found else [0]
    min_needle = min(needle_scores) if needle_scores else 0
    max_needle = max(needle_scores) if needle_scores else 0

    stats = {
        "seed": seed,
        "total_packets": manifest["total_packets"],
        "needles_found": len(found),
        "needles_total": len(manifest["needles"]),
        "false_positives": len(fps),
        "min_needle_score": min_needle,
        "max_needle_score": max_needle,
        "missing": list(missing),
    }

    passed = len(missing) == 0
    return passed, stats


def main():
    parser = argparse.ArgumentParser(description="Chaos needle test runner")
    parser.add_argument("--seeds", type=int, default=5, help="Number of random seeds to test")
    parser.add_argument("--threshold", type=float, default=0.5, help="Beacon detection threshold")
    args = parser.parse_args()

    seeds = list(range(42, 42 + args.seeds))
    all_passed = True
    all_stats = []

    print(f"Chaos Needle Test — {len(seeds)} seeds, threshold={args.threshold}")
    print("=" * 70)

    for seed in seeds:
        passed, stats = run_seed(seed, args.threshold)
        all_stats.append(stats)

        status = "PASS" if passed else "FAIL"
        needle_str = f"{stats['needles_found']}/{stats['needles_total']}"
        print(f"  Seed {seed:3d}: {status}  needles={needle_str}  "
              f"FPs={stats['false_positives']}  "
              f"score=[{stats['min_needle_score']:.3f}-{stats['max_needle_score']:.3f}]  "
              f"packets={stats['total_packets']:,}")

        if not passed:
            all_passed = False
            print(f"           MISSING: {stats['missing']}")

    # Summary
    print("=" * 70)
    total_needles = sum(s["needles_found"] for s in all_stats)
    total_expected = sum(s["needles_total"] for s in all_stats)
    total_fps = sum(s["false_positives"] for s in all_stats)
    min_score = min(s["min_needle_score"] for s in all_stats)
    max_score = max(s["max_needle_score"] for s in all_stats)
    avg_fps = total_fps / len(all_stats)

    print(f"Needles found:     {total_needles}/{total_expected}")
    print(f"Score range:       [{min_score:.3f} - {max_score:.3f}]")
    print(f"Avg FPs per seed:  {avg_fps:.1f}")
    print()

    if all_passed:
        print("ALL SEEDS PASSED — needles always found in the chaos")
    else:
        print("SOME SEEDS FAILED — needles missed")
        sys.exit(1)


if __name__ == "__main__":
    main()
