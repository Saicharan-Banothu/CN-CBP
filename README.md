# 🔬 Network Autopsy

> **A Multi-Parameter Network Failure Diagnosis and Root-Cause Localization Platform**  
> Continuous Active/Passive Telemetry • Network-Specific Adaptive Baselines • Multi-Signal Evidence Correlation • Hop Confidence Attribution • White-Box ML Confirmation • Safe Socket Fault Injection • Empirical Validation Engine

---

## 1. Project Title & Overview

**Network Autopsy** is a small-LAN and lab network fault diagnosis and root-cause localization platform. Rather than acting as an Intrusion Detection System (IDS), cybersecurity monitor, or generic ping dashboard, Network Autopsy systematically answers five critical operational questions whenever network degradation occurs:

1. **What is happening?** (Degradation characterization across Latency, Loss, Jitter, Retransmissions, DNS, TCP, and HTTP).
2. **Where is it happening?** (Hop-by-hop path attribution with confidence intervals, distinguishing LAN gateway bottlenecks from upstream ISP transit).
3. **Why is it happening?** (Multi-signal evidence correlation identifying the exact failure mode across OSI Layers 1–7).
4. **How confident are we?** (Transparent evidence fusion combining expert rules, statistical baseline anomalies, path consistency, and white-box Decision Tree confirmation).
5. **Did it recover?** (Automated post-fault recovery detection and incident lifecycle resolution).

---

## 2. Problem Statement

Modern small-office, home, and academic lab networks suffer from silent, compound failures: bufferbloat congestion, DNS sinkholing, transport-layer packet drops, intermediate routing path flaps, and application server crashes. 

Standard network monitoring tools present major shortcomings:
- **Single-metric false alarms**: Alerting simply because latency exceeds an arbitrary threshold (e.g. `> 60ms`), ignoring network-specific operational norms.
- **Traceroute misattribution**: Blindly blaming intermediate hops that rate-limit ICMP TTL-Exceeded packets, despite forwarding data traffic at full line rate.
- **Disconnected toolchains**: Requiring engineers to manually correlate `ping`, `traceroute`, `tcpdump`, and application logs.
- **Synthetic validation fallacies**: Academic prototypes claiming "100% accuracy" evaluated purely on in-memory synthetic feature vectors, without ever testing against degraded physical or virtual network sockets.

---

## 3. Motivation

Diagnosing network failures requires **multi-parameter synthesis**. A latency increase at the local gateway implies wireless congestion; the same latency increase with zero gateway degradation implies an upstream WAN bottleneck. A TCP connect timeout while ICMP ping succeeds indicates a firewall or closed port; an HTTP 503 response while TCP handshakes complete cleanly isolates an application crash. Network Autopsy automates this multi-layer reasoning in real time.

---

## 4. Core Contributions

1. **Dual Active/Passive Telemetry Store**: Merges active ICMP, Traceroute, TCP handshake, DNS, and HTTP GET probes with passive sniffer metrics (TCP retransmissions, duplicate ACKs, checksum integrity errors).
2. **Network-Specific Adaptive Baselines**: Learns dynamic running means, standard deviations, medians, 95th percentiles, and EWMA statistics per metric, flagging anomalies via statistically defensible deviation percentages rather than hardcoded thresholds.
3. **Corroborated Hop Confidence Scoring**: Evaluates multiple consecutive traceroute runs alongside direct gateway probes and passive transport indicators. Never attributes fault to a single hop without independent corroboration; tags unconfirmed downstream drops as `likely region: hop X–Y (unconfirmed)`.
4. **Explainable Multi-Tier Consensus Engine**: Combines an 8-rule expert classifier with an interpretable CART Decision Tree (`max_depth=6`) that exports white-box if-then rules to plain text for post-mortem viva defense.
5. **Safe Fault Injection Sandbox**: Provides a dedicated loopback proxy (`ControlledNetworkTarget` on port 8085) that safely injects socket-level latency, jitter, packet loss, bandwidth throttling, connection refusal, and HTTP 503 without modifying the user's primary network interface.
6. **Empirical Ground-Truth Validation Engine**: Evaluates diagnostic accuracy, detection latency, localization accuracy, and recovery detection against real degraded OS network sockets, cleanly separated from synthetic unit benchmarks.

---

## 5. End-to-End System Architecture

```
                    REAL NETWORK / TEST TOPOLOGY
                                 │
              ┌──────────────────┴──────────────────┐
              │                                     │
     Active Probes (Layer 3-7)             Passive Packet Sniffer (Layer 2-4)
     • ICMP Gateway & WAN Ping             • TCP Retransmission Tracker
     • TTL Traceroute Sequence             • Duplicate ACK Counter (RFC 5681)
     • TCP Connect Handshake               • TCP RST / FIN Monitor
     • DNS Query Resolution Time           • IP/TCP Checksum Integrity Verifier
     • Raw HTTP GET & TTFB                 • Protocol Distribution Counter
              │                                     │
              └──────────────────┬──────────────────┘
                                 │ Raw Telemetry & Events
                                 ▼
                     METRICS STORE (SQLite WAL Mode)
                     probe_results │ hop_data │ packet_events
                     incidents     │ baselines│ experiments
                                 │
                                 ▼
                    WINDOWED FEATURE AGGREGATOR
                    (20-second rolling sliding windows)
                                 │
                                 ▼
                     ADAPTIVE BASELINE LEARNER
                     (Running Mean, StdDev, Median, EWMA, % Deviation)
                                 │
                                 ▼
                    MULTI-SIGNAL EVIDENCE CORRELATOR
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
  8-Rule Expert            Hop Confidence            Interpretable ML
    Classifier             Scoring Engine             Decision Tree
 (Layer & Cause)         (Corroborated Hops)         (Secondary Conf)
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │
                                 ▼
                       EVIDENCE FUSION LAYER
                     (Consensus & Confidence)
                                 │
                                 ▼
                      INCIDENT LIFECYCLE MANAGER
                DETECTED ➔ CONFIRMED ➔ ONGOING ➔ RESOLVED
                    (Deduplication & Recovery Detection)
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       Live Dashboard     Autopsy Report      Incident Timeline
       (Path Topology &   (Jinja2 Post-Mortem (State Transitions)
       Explainable Grade)  HTML Document)
              ▲
              │
       VALIDATION LAB
              │
       Safe Fault Proxy ────► Ground Truth ────► Evaluation Engine
       (Socket Injections)    Trial Logger        (Precision, Recall, F1,
                                                  Latency, Recovery)
```

---

## 6. Comprehensive Features List

- **Live Freshness Monitor**: Displays data age in seconds, last update timestamp, and visual pulse indicator (`LIVE` vs `STALE DATA`).
- **Explainable Health Score Card**: Network health score (0–100) and letter grade (A–F) accompanied by an expandable deduction breakdown detailing the exact penalty contributed by each anomalous metric.
- **Dynamic Network Path Topology View**: Interactive visual hop sequence (`Local Host` ➔ `Gateway` ➔ `Hop 2` ➔ `Hop 3` ➔ `Destination`) displaying per-hop RTT, loss %, deviation %, and status badges (`HEALTHY`, `SUSPECTED`, `LIKELY_FAULT`, `UNCONFIRMED`). Clicking any hop opens an inspection card.
- **Dual-Axis Telemetry Timeline**: Real-time Chart.js graph displaying live latency alongside its adaptive baseline band and packet loss bars.
- **Incident Deduplication**: Correlates recurring symptom windows under a single canonical incident key, preventing alert storms while tracking total incident duration and occurrence count.
- **Recovery Detection**: Continuously checks active incidents against recovering telemetry; automatically transitions incidents to `RESOLVED` when metrics return to baseline tolerances.
- **Controlled Validation Lab**: UI sandbox supporting 10 safe fault injection scenarios, duration/intensity configuration, step progression tracking, and ground-truth comparison.
- **Strict Separation of Validation Regimes**: Independent tabs for empirical real-network experiments vs. synthetic unit benchmarks, preventing fabricated or misleading metrics.

---

## 7. Data Pipeline & System Flow

```
1. Active Probes & Sniffer run continuously in background worker threads.
2. Probe results and packet events write to SQLite WAL database.
3. Every 10 seconds, WindowAggregator extracts telemetry from [now - 20s, now].
4. BaselineLearner evaluates window metrics against running mean ± 3σ and computes % deviation.
5. HopConfidenceScorer analyzes consecutive traceroute runs for bottleneck corroboration.
6. RuleClassifier evaluates 8 deterministic expert rules; ML Classifier predicts fault class.
7. ReportGenerator checks active incidents for recovery; if unresolved anomalies exist, generates or updates deduplicated incident.
8. Dashboard polls REST APIs (/api/health, /api/latest-metrics, /api/topology, /api/incidents) and renders real-time state.
```

---

## 8. Technology Stack

| Component | Technology | Rationale |
|:---|:---|:---|
| **Backend Framework** | FastAPI + Uvicorn | High-performance asynchronous REST endpoints with automatic OpenAPI documentation. |
| **Telemetry Store** | SQLite 3 (WAL Mode) | Zero-configuration, ACID-compliant local database; eliminates external service dependencies (Redis/Postgres). |
| **Packet Capture** | Scapy + Raw Sockets | Python packet crafting and decoding; supports promiscuous sniffer with graceful socket fallbacks. |
| **Machine Learning** | scikit-learn | Transparent CART `DecisionTreeClassifier` (deployed) and `RandomForestClassifier` (benchmark). |
| **Templating Engine** | Jinja2 | Renders comprehensive standalone HTML autopsy post-mortem reports. |
| **Frontend UI** | HTML5, Vanilla CSS, JS, Chart.js | Lightweight, responsive dark-mode dashboard without heavy Node/React build toolchains. |

---

## 9. Installation & Setup Instructions

### Prerequisites
- Python 3.11, 3.12, or 3.13
- Windows 10/11, Ubuntu Linux, or WSL2

### Clone and Install
```bash
# 1. Clone repository
git clone https://github.com/Saicharan-Banothu/CN-CBP.git
cd CN-CBP

# 2. Install dependencies
pip install -r requirements.txt
```

---

## 10. Linux, WSL2, and Windows Environment Requirements

The platform automatically detects its operating environment at startup:
- **Windows (Native)**: Active probes utilize Windows `ping`, `tracert`, and native TCP/UDP sockets. Fault injection runs safely via the local `ControlledNetworkTarget` socket proxy on port 8085.
- **Linux / WSL2**: Supports Linux kernel Traffic Control (`tc netem`) on dedicated virtual interfaces (e.g. `veth` pairs) when root privileges are available, falling back safely to the socket proxy when unprivileged.

---

## 11. Packet Capture Permissions & Npcap Guidance

- **Windows**: To enable passive TCP retransmission and duplicate ACK sniffing, install [Npcap](https://npcap.com/) with **"Install Npcap in WinPcap API-compatible Mode"** enabled. If Npcap is absent, the system operates in raw socket fallback mode and marks capture capabilities transparently in `/api/environment`.
- **Linux**: Grant packet capture permissions without root:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
  ```

---

## 12. Configuration (`config.yaml`)

Key parameters can be configured in `config.yaml`:
```yaml
storage:
  db_path: "data/autopsy.db"

agent:
  probe_interval_seconds: 10.0
  ping_targets: ["auto_gateway", "8.8.8.8", "1.1.1.1"]
  traceroute_targets: ["8.8.8.8"]
  sniffer:
    interface: null # null selects default interface
    bpf_filter: "ip or arp"

engine:
  window_duration_seconds: 20.0
  eval_interval_seconds: 10.0
  baseline:
    warmup_samples: 15
    z_threshold: 3.0
    alpha_ema: 0.05
```

---

## 13. Running Live Monitoring

Start the full system (active probes, sniffer, diagnosis loop, socket proxy, and web server):
```bash
python main.py
```
Open your browser to:
- **Live Dashboard**: `http://127.0.0.1:8000/`
- **Validation Lab**: `http://127.0.0.1:8000/static/dashboard.html#validation`
- **API Documentation**: `http://127.0.0.1:8000/docs`

---

## 14. Running Demo & Simulation Mode

For offline classroom demonstrations without live network access, the system includes calibrated deterministic scenarios:
```bash
# Execute synthetic unit benchmark across all 9 fault modes
python sandbox/validation_runner.py --mode synthetic --trials 10
```

---

## 15. Running Safe Fault Injection

The platform supports 10 controlled fault scenarios:

| Scenario ID | Name | Mechanism | Expected Affected Layer |
|:---|:---|:---|:---:|
| `HIGH_LATENCY` | Latency Spike (+180ms) | Socket buffer delay | Network |
| `JITTER` | RTT Jitter (35ms variance) | Variable sleep variance | Network |
| `PACKET_LOSS` | Packet Loss (25%) | Random socket drop | Network / Transport |
| `BANDWIDTH_THROTTLING` | Bandwidth Throttle (128 kbps) | Token bucket rate limit | Network |
| `DNS_FAILURE` | DNS Resolver Timeout | Resolver sinkhole redirection | Application / Transport |
| `HTTP_SERVICE_FAILURE` | HTTP 503 Server Crash | Target returns HTTP 503 | Application |
| `TCP_SERVICE_FAILURE` | TCP Port Blocked / Reset | Connection refusal / RST | Transport |
| `ROUTE_CHANGE` | Route Flap / Path Shift | Synthetic path hop mutation | Network |
| `INTERMITTENT_PACKET_LOSS` | Intermittent Burst Drop (40%) | Oscillating drop cycle | Network / Data-Link |
| `COMBINED_FAULT` | Latency + Loss Compound Fault | Simultaneous delay & drop | Network / Transport |

---

## 16. Running Validation Experiments

Execute end-to-end empirical trials against real degraded sockets:
```bash
# Run 1 trial per scenario against real OS sockets
python sandbox/validation_runner.py --mode real --trials 1

# Run 5 trials per scenario
python sandbox/validation_runner.py --mode real --trials 5
```

---

## 17. Evaluation Methodology

Network Autopsy strictly differentiates four separate performance metrics:
1. **Detection Accuracy**: Did the system recognize that a non-normal network condition occurred?
2. **Diagnosis Accuracy**: Did the system correctly classify the specific root cause (e.g. Gateway Congestion vs Upstream ISP)?
3. **Localization Accuracy**: Did the hop-level analysis identify the correct hop or regional boundary?
4. **Recovery Detection Accuracy**: Did the system verify that metrics returned to baseline after fault removal?

---

## 18. Empirical Results

### Real Network Experiments (Degraded OS Sockets)
*Empirical evaluation executed across live OS network sockets (persisted in `data/real_validation_results.json`):*

- **Total Empirical Trials**: 10
- **Diagnosis Accuracy**: 70.0%
- **Detection Rate**: 30.0%
- **Recovery Detection Accuracy**: 100.0%
- **Mean Detection Latency**: 15.73s
- **Mean Recovery Time**: 16.25s

### Synthetic Scenario Benchmark (Unit Tests)
*Algorithmic unit tests evaluated on calibrated feature vectors (`data/synthetic_validation_results.json`):*
- **Total Synthetic Trials**: 90 (10 per class)
- **Overall Accuracy**: 88.9%
- **Per-Class F1-Scores**:
  - DNS Failure: 1.000
  - Upstream ISP Fault: 1.000
  - Target Service Down: 1.000
  - Lossy Link Congestion: 1.000
  - Packet Integrity (CRC): 1.000
  - Route Flap: 1.000
  - Application Layer Failure: 1.000

---

## 19. Machine Learning Methodology & Zero Data Leakage

### 5-Model Comparative Evaluation
To defend architectural choices during viva, 5 distinct diagnostic models are compared:

1. **Static Threshold Baseline**: Fixed heuristic thresholds (fails on network-specific baselines).
2. **Rule-Only Classifier**: 8-rule expert system.
3. **CART Decision Tree (Deployed)**: White-box model (`max_depth=6`) providing 100% auditable if-then rules exported to `data/decision_tree_rules.txt`.
4. **Random Forest Benchmark**: 100-tree ensemble validation upper bound.
5. **Hybrid Rules + Decision Tree**: Multi-tier consensus architecture.

### Data Leakage Prevention
Standard train/test splits that randomly shuffle rolling time windows cause severe data leakage because adjacent 20-second windows from the same incident are auto-correlated. Network Autopsy uses **`GroupShuffleSplit` grouped by unique experiment run ID**, ensuring that entire incident episodes are placed exclusively into either the training or testing partition.

---

## 20. Known Limitations & Academic Honesty

1. **Ethernet FCS / CRC Visibility**: Standard OS socket APIs and Npcap do not expose the physical Ethernet 4-byte Frame Check Sequence (FCS) because network interface cards strip FCS before passing frames to the OS driver. The platform terms this feature **"Packet Integrity Indicators (IP/TCP Checksum Verification)"** rather than claiming physical layer FCS detection.
2. **Traceroute Granularity**: Intermediate routers that rate-limit ICMP time-exceeded messages cannot be localized to a single hop with high confidence. The platform explicitly tags these as `likely region: hop X–Y (unconfirmed)`.
3. **Safe Mode Default**: To prevent disruption to university or home Wi-Fi interfaces, the platform defaults to isolated socket proxy fault injection rather than kernel-level `tc qdisc` modifications.

---

## 21. Computer Networks Syllabus Mapping

| Syllabus Concept | Implementation in Network Autopsy | Source File |
|:---|:---|:---|
| **OSI Reference Model** | Multi-layer diagnosis mapping symptoms to Data-Link, Network, Transport, and Application layers. | `engine/rules.py` |
| **Error Detection & Checksums** | Software recalculation and verification of 16-bit Internet checksums (RFC 1071) for IP, TCP, and UDP headers. | `agent/passive_capture.py` |
| **Flow Control & ARQ** | Detection of duplicate ACKs (Fast Retransmit trigger, RFC 5681) and TCP retransmission tracking. | `agent/passive_capture.py` |
| **IPv4 Header & TTL** | TTL-incrementing traceroute probes measuring hop-by-hop round-trip delay. | `agent/active_probes.py` |
| **Routing & Path Flapping** | Route change detection comparing ordered hop IP sequences across consecutive traceroute runs. | `engine/windowing.py` |
| **Transport Layer Handshakes** | Direct TCP 3-way handshake latency (SYN ➔ SYN-ACK) and connection refusal (RST) detection. | `agent/active_probes.py` |
| **Application Layer Protocols** | Wire-format DNS query resolution and raw HTTP/1.1 transaction measurement with TTFB tracking. | `agent/active_probes.py` |
| **Network Emulation & Queuing** | Token bucket rate limiting, jitter simulation, and socket-level packet drop injection. | `sandbox/local_fault_proxy.py` |

---

## 22. Project Directory Structure

```
CN_CBP/
├── README.md                      # Comprehensive academic & operational documentation
├── requirements.txt               # Pinned Python dependencies
├── config.yaml                    # System configuration parameters
├── main.py                        # Unified runtime entry point
├── agent/
│   ├── active_probes.py           # ICMP, Traceroute, TCP, DNS, HTTP active probe implementations
│   ├── passive_capture.py         # Scapy packet sniffer (retransmissions, dup ACKs, checksums)
│   └── probe_scheduler.py         # Multi-target background probe orchestrator
├── storage/
│   ├── db.py                      # Thread-safe SQLite schema, WAL mode, indexing, and CRUD
│   └── models.py                  # Dataclasses: ProbeResult, HopData, Incident, ExperimentRecord
├── engine/
│   ├── windowing.py               # 20-second rolling window feature aggregation
│   ├── baseline.py                # Adaptive baseline learner (Mean, StdDev, Median, EWMA)
│   ├── rules.py                   # 8-rule expert root-cause diagnosis classifier
│   ├── hop_confidence.py          # Multi-run hop attribution confidence scorer
│   ├── ml_classifier.py           # 5-model ML comparison & leakage-free group evaluation
│   └── report_generator.py        # Incident lifecycle manager & Jinja2 autopsy report generator
├── sandbox/
│   ├── fault_injection.py         # SafeFaultController with safe mode & dry-run protections
│   ├── local_fault_proxy.py       # ControlledNetworkTarget socket proxy (port 8085)
│   ├── service_killer.py          # Controlled DNS and HTTP service failure simulators
│   ├── route_flap_sim.py          # Route oscillation simulator
│   └── validation_runner.py       # End-to-end empirical and synthetic experiment runner
├── webapp/
│   ├── server.py                  # FastAPI REST endpoints & diagnostics
│   ├── static/
│   │   ├── dashboard.html         # Live operations dashboard
│   │   ├── dashboard.js           # Live polling, dynamic topology, & Chart.js controller
│   │   └── style.css              # Responsive dark-mode engineering theme
│   └── templates/
│       └── incident_report.html   # Standalone HTML Autopsy Post-Mortem report template
├── data/
│   ├── autopsy.db                 # SQLite database
│   ├── decision_tree_rules.txt    # Exported white-box Decision Tree rules
│   ├── ml_comparison.json         # 5-model comparative evaluation metrics
│   ├── real_validation_results.json # Empirical OS socket experiment records
│   └── synthetic_validation_results.json # Synthetic unit benchmark results
└── tests/
    └── test_engine.py             # 7 automated unit tests covering pipeline & socket proxy
```

---

## 23. Automated Test Suite

Run the full automated test suite:
```bash
python -m pytest -v tests/test_engine.py
```
**Test Coverage**:
- `test_windowing_aggregation`: Verifies mathematical accuracy of rolling-window metric aggregation.
- `test_adaptive_baseline_learner`: Verifies warm-up sample handling and 3σ deviation anomaly triggers.
- `test_rule_engine_rules`: Verifies expert system rule activation across all fault conditions.
- `test_hop_confidence_scoring`: Verifies single-run capping, regional labeling, and multi-signal corroboration.
- `test_incident_deduplication_lifecycle`: Verifies deduplication key reuse and recovery state transition.
- `test_safe_fault_proxy_socket_degradation`: Verifies socket latency injection and HTTP 503 status code responses.
- `test_ml_leakage_free_split`: Verifies `GroupShuffleSplit` across incident runs.

---

## 24. Professor Demonstration Script (Viva Walkthrough)

Follow this 5-minute sequence for laboratory or viva evaluation:

1. **Launch Platform**: Run `python main.py` and open `http://127.0.0.1:8000/`.
2. **Demonstrate Healthy State**:
   - Show the **Health Score Card**: 100/100, Grade A, "Network Optimal".
   - Show the **Dynamic Network Path Topology**: `Local Host` ➔ `Gateway` ➔ `Intermediate Hops` ➔ `Target Reference`, all tagged `HEALTHY`.
   - Show the **Telemetry Tiles**: Latency within baseline, 0.0% loss.
3. **Inspect Diagnostics**:
   - Click `🖥️ Diagnostics` in the top header.
   - Show the operating system, Python version, packet capture mode, and safe proxy state on port 8085.
4. **Execute Controlled Fault in Validation Lab**:
   - Scroll to **Controlled Fault Validation Lab**.
   - Select scenario: `Packet Loss (25%)` on `127.0.0.1:8085`.
   - Click `🧪 Run Experiment Trial`.
   - Watch the 5-step live trial stepper advance: `Injected` ➔ `Degraded` ➔ `Probed` ➔ `Diagnosed` ➔ `Recovered`.
5. **Inspect Live Degradation**:
   - Observe the live health score drop and inspect the **Deductions Breakdown Drawer**.
   - Point out the active incident banner: `🚨 ACTIVE INCIDENT DETECTED`.
6. **Open Autopsy Report**:
   - Click `🔬 Inspect Autopsy Report`.
   - Demonstrate the **Multi-Signal Evidence Matrix**, **Incident Timeline**, and **Remediation Plan**.
7. **Verify Recovery**:
   - Click `🔄 Reset Baseline`.
   - Observe the active incident transition to `RESOLVED` with duration recorded.
8. **Show Academic Validation & ML Tabs**:
   - Under **Validation Results**, show the **Real Network Experiments** tab (empirical metrics) vs. the **Synthetic Benchmark** tab.
   - Under the **ML Comparison** tab, show the `GroupShuffleSplit` leakage-prevention methodology and the white-box CART Decision Tree rules.
