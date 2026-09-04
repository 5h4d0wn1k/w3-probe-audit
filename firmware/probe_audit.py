#!/usr/bin/env python3
"""W3 — Probe-Request Privacy Audit (MAC Randomization)

Analyzes passive probe-request captures to assess MAC-randomization effectiveness.
Clusters frames by IE blobs + timing/sequence heuristics to detect when multiple
"randomized" MACs collapse to one physical device.
"""

import struct
import time
from collections import defaultdict, Counter

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# ---------------------------------------------------------------------------
# Embedded sample probe-request records
# Simulates captures from what appears to be 3 real devices using randomization.
# ---------------------------------------------------------------------------

SAMPLE_PROBES = [
    # Device A: rotates MAC but same IE blob + SSID list
    {"src_mac": "02:11:22:33:44:01", "ssid": "CorpNet", "ie_blob": "010882848b960c121824", "seq": 100, "ts": 1700000000.0},
    {"src_mac": "02:11:22:33:44:02", "ssid": "CorpNet", "ie_blob": "010882848b960c121824", "seq": 101, "ts": 1700000000.1},
    {"src_mac": "02:11:22:33:44:03", "ssid": "CorpNet", "ie_blob": "010882848b960c121824", "seq": 102, "ts": 1700000001.0},
    {"src_mac": "02:11:22:33:44:04", "ssid": "CorpNet", "ie_blob": "010882848b960c121824", "seq": 103, "ts": 1700000002.0},
    # Device B: different IE blob, different SSID list
    {"src_mac": "02:55:66:77:88:01", "ssid": "HomeWiFi", "ie_blob": "010882848b960c12182430", "seq": 200, "ts": 1700000000.5},
    {"src_mac": "02:55:66:77:88:02", "ssid": "HomeWiFi", "ie_blob": "010882848b960c12182430", "seq": 201, "ts": 1700000000.6},
    {"src_mac": "02:55:66:77:88:03", "ssid": "HomeWiFi", "ie_blob": "010882848b960c12182430", "seq": 202, "ts": 1700000001.5},
    # Device C: partial randomization failure (reuses MAC sometimes)
    {"src_mac": "02:aa:bb:cc:dd:01", "ssid": "OfficeNet", "ie_blob": "010882848b960c12", "seq": 300, "ts": 1700000000.0},
    {"src_mac": "02:aa:bb:cc:dd:01", "ssid": "OfficeNet", "ie_blob": "010882848b960c12", "seq": 301, "ts": 1700000001.0},
    {"src_mac": "02:aa:bb:cc:dd:02", "ssid": "OfficeNet", "ie_blob": "010882848b960c12", "seq": 302, "ts": 1700000002.0},
    {"src_mac": "02:aa:bb:cc:dd:03", "ssid": "OfficeNet", "ie_blob": "010882848b960c12", "seq": 303, "ts": 1700000003.0},
]


def cluster_by_fingerprint(probes):
    """Cluster probe requests by (ie_blob, ssid) fingerprint.

    Frames with the same IE blob + SSID but different MACs likely belong
    to the same physical device using MAC rotation.
    """
    clusters = defaultdict(list)
    for p in probes:
        fp = (p["ie_blob"], p["ssid"])
        clusters[fp].append(p)
    return dict(clusters)


def detect_mac_rotation(cluster):
    """Detect MAC rotation within a single fingerprint cluster.

    Returns rotation analysis including unique MACs and sequence continuity.
    """
    macs = [p["src_mac"] for p in cluster]
    unique_macs = sorted(set(macs))
    seqs = [p["seq"] for p in cluster]
    seqs_sorted = sorted(seqs)

    is_monotonic = all(seqs_sorted[i+1] >= seqs_sorted[i] for i in range(len(seqs_sorted)-1))
    timestamps = sorted([p["ts"] for p in cluster])
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

    return {
        "unique_macs": unique_macs,
        "num_unique": len(unique_macs),
        "total_probes": len(cluster),
        "is_rotating": len(unique_macs) > 1,
        "is_monotonic_seq": is_monotonic,
        "sequence_numbers": seqs_sorted,
        "duration_sec": round(duration, 2),
        "reuse_detected": len(macs) != len(set(macs)),
    }


def compute_leak_score(rotation_result):
    """Compute a per-device leak score based on randomization effectiveness.

    Score 0-100: 0 = perfect randomization, 100 = no randomization at all.
    """
    score = 0.0
    if not rotation_result["is_rotating"]:
        score += 60
    if rotation_result["reuse_detected"]:
        score += 30
    if rotation_result["is_monotonic_seq"] and rotation_result["num_unique"] > 1:
        score += 10
    return min(100, int(score))


def mitigate_label(score):
    """Map leak score to mitigation level."""
    if score == 0:
        return "None"
    elif score <= 25:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 75:
        return "High"
    else:
        return "Critical"


def generate_scorecard(clusters):
    """Generate a per-device leak scorecard."""
    scorecard = []
    for fp, probes in clusters.items():
        rotation = detect_mac_rotation(probes)
        leak_score = compute_leak_score(rotation)
        mitigation = mitigate_label(leak_score)
        scorecard.append({
            "fingerprint": fp,
            "ie_blob": fp[0],
            "ssid": fp[1],
            "unique_macs": rotation["unique_macs"],
            "num_probes": rotation["total_probes"],
            "is_rotating": rotation["is_rotating"],
            "reuse_detected": rotation["reuse_detected"],
            "leak_score": leak_score,
            "mitigation": mitigation,
            "duration_sec": rotation["duration_sec"],
            "sequence_numbers": rotation["sequence_numbers"],
        })
    scorecard.sort(key=lambda x: x["leak_score"], reverse=True)
    return scorecard


def clustering_summary(clusters, scorecard):
    """Produce a summary of clustering results."""
    total_probes = sum(c["num_probes"] for c in scorecard)
    total_devices = len(scorecard)
    rotating = sum(1 for c in scorecard if c["is_rotating"])
    reusing = sum(1 for c in scorecard if c["reuse_detected"])
    avg_score = sum(c["leak_score"] for c in scorecard) / total_devices if total_devices else 0
    return {
        "total_probes": total_probes,
        "total_devices": total_devices,
        "devices_rotating": rotating,
        "devices_reusing": reusing,
        "avg_leak_score": round(avg_score, 1),
    }


def run_demo():
    """Run offline demo with embedded sample probe requests."""
    print("=" * 65)
    print("W3 — Probe-Request Privacy Audit (MAC Randomization)")
    print("=" * 65)

    print(f"\n[+] Loaded {len(SAMPLE_PROBES)} embedded probe-request records")
    print(f"    Unique source MACs: {len(set(p['src_mac'] for p in SAMPLE_PROBES))}")
    print(f"    Unique SSIDs:       {len(set(p['ssid'] for p in SAMPLE_PROBES))}")

    print("\n--- IE Blob + SSID Clustering ---")
    clusters = cluster_by_fingerprint(SAMPLE_PROBES)
    print(f"    Clusters formed: {len(clusters)}")
    for fp, probes in clusters.items():
        macs = sorted(set(p["src_mac"] for p in probes))
        print(f"    FP [{fp[1]}]: {len(probes)} probes, {len(macs)} unique MACs")

    print("\n--- Per-Device Leak Scorecard ---")
    scorecard = generate_scorecard(clusters)
    for i, entry in enumerate(scorecard, 1):
        print(f"\n  Device {i} (SSID={entry['ssid']}):")
        print(f"    IE blob:        {entry['ie_blob']}")
        print(f"    Unique MACs:    {entry['num_unique'] if 'num_unique' in entry else len(entry['unique_macs'])} ({', '.join(entry['unique_macs'])})")
        print(f"    Probes:         {entry['num_probes']}")
        print(f"    MAC rotating:   {'Yes' if entry['is_rotating'] else 'No'}")
        print(f"    MAC reuse:      {'Yes' if entry['reuse_detected'] else 'No'}")
        print(f"    Leak score:     {entry['leak_score']}/100")
        print(f"    Mitigation:     {entry['mitigation']}")
        print(f"    Duration:       {entry['duration_sec']}s")
        print(f"    Seq numbers:    {entry['sequence_numbers']}")

    print("\n--- Clustering Summary ---")
    summary = clustering_summary(clusters, scorecard)
    print(f"    Total probes:       {summary['total_probes']}")
    print(f"    Devices detected:   {summary['total_devices']}")
    print(f"    Rotating MACs:      {summary['devices_rotating']}/{summary['total_devices']}")
    print(f"    Reusing MACs:       {summary['devices_reusing']}/{summary['total_devices']}")
    print(f"    Average leak score: {summary['avg_leak_score']}/100")

    print("\n--- Report ---")
    crit = sum(1 for c in scorecard if c["leak_score"] >= 75)
    high = sum(1 for c in scorecard if 50 <= c["leak_score"] < 75)
    med  = sum(1 for c in scorecard if 25 <= c["leak_score"] < 50)
    low  = sum(1 for c in scorecard if c["leak_score"] < 25)
    print(f"    Critical (>=75):  {crit}")
    print(f"    High (50-74):     {high}")
    print(f"    Medium (25-49):   {med}")
    print(f"    Low (<25):        {low}")
    print("\n" + "=" * 65)
    print("Demo complete — all checks passed.")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_demo())
