#!/usr/bin/env python3
"""Byte-exact unit tests for w3-probe-audit."""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from firmware import probe_audit as pa
from firmware import frame_core as fc


class ProbeBuildTest(unittest.TestCase):
    def test_probe_frame_roundtrip(self):
        raw = fc.build_probe_request(ssid="lab-test-net", sa="02:11:22:33:44:01",
                                     seq_num=5)
        fields, ssid = fc.parse_probe_request(raw)
        self.assertEqual(ssid, "lab-test-net")
        self.assertEqual(fields["sa"], "02:11:22:33:44:01")
        self.assertEqual(fields["seq_num"], 5)

    def test_corpus_frames_parse(self):
        for f in pa.build_probe_corpus():
            data = f["data"]
            self.assertTrue(fc.verify_fcs(data))
            fields, _ = fc.parse_probe_request(data[:-4])
            self.assertEqual(fields["subtype_val"], fc.FC_SUBTYPE_PROBE_REQ)
            self.assertEqual(fields["sa"], f["mac"])

    def test_same_fingerprint_within_device(self):
        dev = pa.DEVICE_A
        fps = {pa.fingerprint(f["data"]) for f in pa.build_probe_corpus([dev])}
        self.assertEqual(len(fps), 1)


class ClusteringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        probes = []
        for f in pa.build_probe_corpus():
            probes.append({"kind": "probe-request", "sa": f["mac"], "ssid": f["ssid"],
                           "seq": f["seq"], "ts": f["ts"],
                           "fingerprint": pa.fingerprint(f["data"])})
        cls.probes = probes

    def test_three_devices_clustered(self):
        clusters = pa.cluster_by_fingerprint(self.probes)
        self.assertEqual(len(clusters), 3)

    def test_device_c_reuse_detected(self):
        clusters = pa.cluster_by_fingerprint(self.probes)
        scorecard = pa.generate_scorecard(clusters)
        dev_c = [e for e in scorecard if e["ssid"] == "lab-officenet"][0]
        self.assertTrue(dev_c["reuse_detected"])
        self.assertGreater(dev_c["leak_score"], 0)

    def test_device_c_has_fewer_unique_macs(self):
        clusters = pa.cluster_by_fingerprint(self.probes)
        scorecard = pa.generate_scorecard(clusters)
        dev_c = [e for e in scorecard if e["ssid"] == "lab-officenet"][0]
        self.assertEqual(len(dev_c["unique_macs"]), 3)   # 4 probes, 3 unique (1 reuse)


class PcapTest(unittest.TestCase):
    def test_pcap_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "probes.pcap")
            frames = pa.build_probe_corpus()
            n = pa.write_probe_pcap(frames, path)
            self.assertEqual(n, len(frames))
            parsed = pa.read_probe_pcap(path)
            probes = [p for p in parsed if p["kind"] == "probe-request"]
            self.assertEqual(len(probes), len(frames))


class ReportTest(unittest.TestCase):
    def test_result_json(self):
        r = pa.run_audit("synthetic", None)
        json.dumps(r, default=str)
        self.assertEqual(r["clusters"], 3)

    def test_output_mode_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "o.json")
            rc = pa.main(["--source", "synthetic", "--json", out])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))

    def test_demo_exit_zero(self):
        self.assertEqual(pa.run_demo(), 0)


if __name__ == "__main__":
    unittest.main()
