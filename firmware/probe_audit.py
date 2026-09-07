#!/usr/bin/env python3
"""W3 — Probe-Request Privacy Audit (MAC Randomization).

Byte-level probe-request engineering + passive-clustering audit.

Builds real 802.11 probe-request frames offscreen (frame_core) that model
multiple physical devices rotating MAC addresses, then parses them byte-exact,
clusters frames by IE-blob + SSID fingerprint to collapse randomized MACs back
to physical devices, and computes a per-device privacy leak score.

No radio emitted; all probing is synthesized as bytes on the host CPU.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from collections import defaultdict

try:
    from firmware import frame_core as fc
except ImportError:
    try:
        import frame_core as fc
    except ImportError:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "firmware"))
        import frame_core as fc

# ----------------------------------------------------------------------
# Probe-request corpus (3 physical devices with varying randomization)
# ----------------------------------------------------------------------
# Each record: base SSID + list of (rotated MAC, seq, ts). IE blob is built
# from the same SSID + rates so the fingerprint is stable per device.

DEVICE_A = {"name": "device-a", "ssid": "lab-corponly", "macs": [
    ("02:11:22:33:44:01", 100, 1700000000.0),
    ("02:11:22:33:44:02", 101, 1700000000.1),
    ("02:11:22:33:44:03", 102, 1700000001.0),
    ("02:11:22:33:44:04", 103, 1700000002.0),
]}
DEVICE_B = {"name": "device-b", "ssid": "lab-homewifi", "macs": [
    ("02:55:66:77:88:01", 200, 1700000000.5),
    ("02:55:66:77:88:02", 201, 1700000000.6),
    ("02:55:66:77:88:03", 202, 1700000001.5),
]}
DEVICE_C = {"name": "device-c", "ssid": "lab-officenet", "macs": [
    ("02:aa:bb:cc:dd:01", 300, 1700000000.0),
    ("02:aa:bb:cc:dd:01", 301, 1700000001.0),   # reuse → randomization failure
    ("02:aa:bb:cc:dd:02", 302, 1700000002.0),
    ("02:aa:bb:cc:dd:03", 303, 1700000003.0),
]}

DEVICES = [DEVICE_A, DEVICE_B, DEVICE_C]


def build_probe_corpus(devices=None) -> list[dict]:
    """Build a set of byte-exact probe-request frames from device definitions."""
    devices = devices or DEVICES
    frames = []
    for dev in devices:
        for (mac, seq, ts) in dev["macs"]:
            raw = fc.build_probe_request(ssid=dev["ssid"], sa=mac, seq_num=seq)
            raw += fc.fcs(raw)
            frames.append({"device": dev["name"], "ssid": dev["ssid"],
                           "mac": mac, "seq": seq, "ts": ts, "data": raw})
    return frames


def fingerprint(data: bytes) -> str:
    """Deterministic fingerprint from the frame payload (IE blob) minus FCS."""
    if fc.verify_fcs(data):
        data = data[:-4]
    return data[24:].hex()          # skip the 24-byte management header


def write_probe_pcap(frames: list[dict], path: str) -> int:
    fc.write_pcap(path, [f["data"] for f in frames], ts=frames[0]["ts"])
    return len(frames)


def read_probe_pcap(path: str) -> list[dict]:
    """Parse probe-request frames back from a pcap fixture (byte-exact)."""
    out = []
    for rec in fc.read_pcap(path):
        data = rec["data"]
        try:
            if fc.verify_fcs(data):
                data = data[:-4]
            fields, _rest = fc.parse_mgmt_header(data)
            if fields["subtype_val"] != fc.FC_SUBTYPE_PROBE_REQ:
                out.append({"kind": "ignored", "subtype": fields["subtype_val"],
                            "ts": rec["ts"]})
                continue
            pfields, ssid = fc.parse_probe_request(data)
            out.append({"kind": "probe-request", "sa": pfields["sa"],
                        "ssid": ssid or "", "seq": pfields["seq_num"],
                        "ts": rec["ts"], "fingerprint": fingerprint(data)})
        except ValueError:
            out.append({"kind": "unknown", "ts": rec["ts"]})
    return out


# ----------------------------------------------------------------------
# Clustering / leak scoring (kept from original, now on parsed probes)
# ----------------------------------------------------------------------


def cluster_by_fingerprint(probes: list[dict]) -> dict:
    clusters = defaultdict(list)
    for p in probes:
        if p["kind"] != "probe-request":
            continue
        fp = (p["fingerprint"], p["ssid"])
        clusters[fp].append(p)
    return dict(clusters)


def detect_mac_rotation(cluster: list[dict]) -> dict:
    macs = [p["sa"] for p in cluster]
    unique = sorted(set(macs))
    seqs = sorted(p["seq"] for p in cluster)
    timestamps = sorted(p["ts"] for p in cluster)
    duration = (timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0
    is_monotonic = all(seqs[i + 1] >= seqs[i] for i in range(len(seqs) - 1))
    return {
        "unique_macs": unique,
        "num_unique": len(unique),
        "total_probes": len(cluster),
        "is_rotating": len(unique) > 1,
        "is_monotonic_seq": is_monotonic,
        "sequence_numbers": seqs,
        "duration_sec": round(duration, 2),
        "reuse_detected": len(macs) != len(set(macs)),
    }


def compute_leak_score(rot: dict) -> int:
    score = 0.0
    if not rot["is_rotating"]:
        score += 60
    if rot["reuse_detected"]:
        score += 30
    if rot["is_monotonic_seq"] and rot["num_unique"] > 1:
        score += 10
    return min(100, int(score))


def mitigate_label(score: int) -> str:
    if score == 0:
        return "None"
    if score <= 25:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 75:
        return "High"
    return "Critical"


def generate_scorecard(clusters: dict) -> list[dict]:
    scorecard = []
    for fp, probes in clusters.items():
        rot = detect_mac_rotation(probes)
        score = compute_leak_score(rot)
        scorecard.append({
            "ssid": fp[1], "fingerprint": fp[0],
            "unique_macs": rot["unique_macs"], "num_probes": rot["total_probes"],
            "is_rotating": rot["is_rotating"], "reuse_detected": rot["reuse_detected"],
            "leak_score": score, "mitigation": mitigate_label(score),
            "duration_sec": rot["duration_sec"], "sequence_numbers": rot["sequence_numbers"],
        })
    scorecard.sort(key=lambda x: x["leak_score"], reverse=True)
    return scorecard


def clustering_summary(clusters: dict, scorecard: list[dict]) -> dict:
    total_probes = sum(c["num_probes"] for c in scorecard)
    total_devices = len(scorecard)
    rotating = sum(1 for c in scorecard if c["is_rotating"])
    reusing = sum(1 for c in scorecard if c["reuse_detected"])
    avg = (sum(c["leak_score"] for c in scorecard) / total_devices) if total_devices else 0
    return {"total_probes": total_probes, "total_devices": total_devices,
            "devices_rotating": rotating, "devices_reusing": reusing,
            "avg_leak_score": round(avg, 1)}


# ----------------------------------------------------------------------
# CLI / demo
# ----------------------------------------------------------------------


def run_audit(source: str, pcap_path: str | None) -> dict:
    if source == "pcap":
        if not pcap_path or not os.path.exists(pcap_path):
            raise FileNotFoundError(f"pcap fixture not found: {pcap_path}")
        probes = read_probe_pcap(pcap_path)
        origin = f"pcap:{pcap_path}"
    else:
        probes = []
        for f in build_probe_corpus():
            probes.append({"kind": "probe-request", "sa": f["mac"],
                           "ssid": f["ssid"], "seq": f["seq"], "ts": f["ts"],
                           "fingerprint": fingerprint(f["data"])})
        origin = "byte-exact builders"

    clusters = cluster_by_fingerprint(probes)
    scorecard = generate_scorecard(clusters)
    summary = clustering_summary(clusters, scorecard)
    return {
        "name": "w3-probe-audit",
        "radio_emitted": False,
        "origin": origin,
        "probes_parsed": len(probes),
        "clusters": len(clusters),
        "scorecard": scorecard,
        "summary": summary,
    }


def build_args_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="w3-probe-audit",
        description="MAC-randomization probe-request privacy audit over byte-exact frames "
                    "(pure-stdlib bytes; offline; no radio).")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--source", choices=["synthetic", "pcap"], default="synthetic",
                   help="frame source: byte-exact builders (default) or a pcap fixture.")
    p.add_argument("--pcap", metavar="PATH", help="pcap fixture to read (with --source pcap).")
    p.add_argument("--write-pcap", metavar="PATH", help="write the synthetic probe corpus.")
    p.add_argument("--json", metavar="PATH", help="write JSON report.")
    return p


def print_report(result: dict) -> None:
    print("=" * 66)
    print("W3 — Probe-Request Privacy Audit (MAC Randomization)")
    print("=" * 66)
    print(f"\n[+] Source: {result['origin']}   (radio_emitted=False)")
    print(f"[+] Probes parsed: {result['probes_parsed']}   Clusters: {result['clusters']}\n")
    for i, e in enumerate(result["scorecard"], 1):
        print(f"  Device {i} (SSID={e['ssid']}):")
        print(f"    Unique MACs:  {len(e['unique_macs'])}  {', '.join(e['unique_macs'])}")
        print(f"    Probes:       {e['num_probes']}   Rotating: {'yes' if e['is_rotating'] else 'no'}")
        print(f"    MAC reuse:    {'yes' if e['reuse_detected'] else 'no'}")
        print(f"    Leak score:   {e['leak_score']}/100  ({e['mitigation']})")
        print(f"    Duration:     {e['duration_sec']}s   Seq: {e['sequence_numbers']}")
    s = result["summary"]
    print("\n[+] Summary")
    print(f"    Total probes:       {s['total_probes']}")
    print(f"    Devices detected:   {s['total_devices']}")
    print(f"    Rotating MACs:      {s['devices_rotating']}/{s['total_devices']}")
    print(f"    Reusing MACs:       {s['devices_reusing']}/{s['total_devices']}")
    print(f"    Avg leak score:     {s['avg_leak_score']}/100")
    print("\nOffline audit complete — no radio emitted.", "(all checks deterministic)")
    print("=" * 66)


def main(argv=None) -> int:
    args = build_args_parser().parse_args(argv)
    try:
        result = run_audit(args.source, args.pcap)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print_report(result)
    if args.write_pcap:
        n = write_probe_pcap(build_probe_corpus(), args.write_pcap)
        print(f"\n[+] probe corpus fixture -> {args.write_pcap} ({n} frames)")
    if args.json:
        d = os.path.dirname(args.json)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2, default=str)
    return 0


def run_demo() -> int:
    return main(["--source", "synthetic"])


if __name__ == "__main__":
    raise SystemExit(main())
