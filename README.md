# W3 — Probe-Request Privacy Audit (MAC Randomization) `w3-probe-audit`

Passive probe-request analysis to assess MAC-randomization effectiveness and detect device identity leaks.

## Overview

This project implements a privacy audit tool for 802.11 probe requests:
- **IE blob clustering**: Groups probe requests by Information Element content + SSID to identify physical devices
- **MAC rotation detection**: Identifies when multiple "randomized" MACs collapse to one device
- **Leak scoring**: Per-device scorecard quantifying randomization effectiveness (0-100)
- **Mitigation assessment**: Labels devices by leak severity (None/Low/Medium/High/Critical)
- **Sequence analysis**: Uses 802.11 sequence numbers to confirm device continuity
- **Timing correlation**: Time-window analysis to detect rapid MAC cycling

## Features

- **Fingerprint clustering**: Groups probes by IE blob + SSID for device-level analysis
- **MAC reuse detection**: Flags partial randomization failures where MACs are reused
- **Leak scorecard**: Per-device 0-100 scoring with mitigation level classification
- **Sequence-number continuity**: Verifies logical frame ordering across MAC rotations
- **Duration analysis**: Measures time span of observed MAC rotations per device
- **Aggregate statistics**: Device counts, rotation rates, average leak scores
- **Offline demo**: 12 embedded probe records from 3 simulated devices

## Installation

```bash
# No external dependencies — Python 3.6+ standard library only
# Optional: numpy for advanced clustering (gracefully degraded if absent)
python3 firmware/probe_audit.py
```

## Usage

```bash
# Run the synthetic probe-privacy audit (byte-exact frame corpus)
python3 firmware/probe_audit.py --source synthetic --json reports/w3.json

# Write the probe corpus to a pcap fixture, then re-audit from the fixture
python3 firmware/probe_audit.py --write-pcap reports/probes.pcap
python3 firmware/probe_audit.py --source pcap --pcap reports/probes.pcap

# Byte-exact unit tests
python3 -m unittest discover -s tests
```

```python
from firmware.probe_audit import cluster_by_fingerprint, generate_scorecard, compute_leak_score

# Cluster probes by IE blob + SSID
clusters = cluster_by_fingerprint(probe_list)

# Generate leak scorecard
scorecard = generate_scorecard(clusters)
```

## Example Output

```
=================================================================
W3 — Probe-Request Privacy Audit (MAC Randomization)
=================================================================

[+] Loaded 12 embedded probe-request records
    Unique source MACs: 10
    Unique SSIDs:       3

--- IE Blob + SSID Clustering ---
    Clusters formed: 3
    FP [CorpNet]: 4 probes, 4 unique MACs
    FP [HomeWiFi]: 3 probes, 3 unique MACs
    FP [OfficeNet]: 4 probes, 3 unique MACs

--- Per-Device Leak Scorecard ---

  Device 1 (SSID=OfficeNet):
    Unique MACs:    3 (02:aa:bb:cc:dd:01, 02:aa:bb:cc:dd:02, ...)
    MAC rotating:   Yes
    MAC reuse:      Yes
    Leak score:     40/100
    Mitigation:     Medium

  Device 2 (SSID=CorpNet):
    Leak score:     10/100
    Mitigation:     Low

  Device 3 (SSID=HomeWiFi):
    Leak score:     10/100
    Mitigation:     Low

--- Clustering Summary ---
    Total probes:       12
    Devices detected:   3
    Rotating MACs:      3/3
    Reusing MACs:       1/3
    Average leak score: 20.0/100
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission before performing wireless device tracking or fingerprinting
- Passive probe-request capture and analysis on networks you do not own may violate privacy laws
- This tool should ONLY be used on networks you own or have written authorization to audit

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized interception of network traffic for tracking purposes may constitute illegal access
- **Wiretap Act (18 U.S.C. § 2511)**: Intercepting electronic communications without consent is prohibited; tracking devices via probe requests may fall under this statute
- **Electronic Communications Privacy Act (ECPA)**: Protects the privacy of wire, oral, and electronic communications
- **State Laws**: Many states have additional wiretapping and privacy statutes

### Acceptable Use
- Auditing MAC-randomization effectiveness on your own devices
- Authorized penetration testing with written scope
- Academic research in controlled environments
- Privacy-focused security education and training

### Prohibited Use
- Tracking individuals' movements via probe requests without authorization
- Using captured probe data for commercial surveillance
- Any activity that violates applicable privacy laws or regulations
- Collecting probe frames from networks you do not own or are not authorized to audit

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## Live Lab Test Plan

This repo is a byte-level engine + simulation tool: probe-request frames are *built* and *parsed*
offscreen — no capture, no radio.

Offline (this repo, no radio):
1. `python3 firmware/probe_audit.py --source synthetic --json reports/w3.json` — build 11
   byte-exact probe frames across 3 synthetic devices, cluster them, print the leak scorecard
   (exit 0), inspect `reports/`.
2. `python3 -m unittest discover -s tests` — byte-exact unit tests pass (exit 0).
3. `python3 firmware/probe_audit.py --source pcap --pcap reports/probes.pcap` — after running
   with `--write-pcap reports/probes.pcap`, re-audit from the fixture and confirm identical
   results (deterministic round-trip).

Authorized lab (only with capture rights + written scope):
4. On a network you own, capture real probe requests with a monitor-mode NIC, convert them to
   a pcap, and feed them to `--source pcap`. Confirm the clustering collapses rotated MACs to
   physical devices as the synthetic corpus does.
5. `green = permitted`: only ever analyze frames captured with the owner's written
   authorization; never track a specific individual's device without consent.

## Metrics

- Frame type engineered byte-exact: probe request (management subtype 4)
- Collection corpus: 3 devices, 11 frames; device-C models MAC reuse (randomization failure)
- pcap write/read round-trip: synthetic corpus -> fixture -> identical parse
- Clustering: by IE-blob fingerprint + SSID; leak score 0-100, mitigation tiering
- Deterministic offline: all frame bytes from builders; no wall-clock randomness

- Test suite: `python3 -m unittest discover -s tests`
- Reports: `reports/` (gitignored)

## License

MIT
