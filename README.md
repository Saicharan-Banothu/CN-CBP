# 🌐 Network Autopsy

> **A Professional Network Observability, Multi-Signal Fault Diagnosis, and Root-Cause Localization Platform**  
> Continuous Active/Passive Telemetry • Adaptive Network Baselines • Multi-Signal Evidence Fusion • Corroborated Hop Attribution • White-Box Decision Tree ML • Safe Socket Fault Sandbox • Clean Separation of Empirical vs. Synthetic Validation

---

## 1. Project Overview

**Network Autopsy** is a network observability and fault-diagnosis platform that combines active network probing, passive traffic evidence, adaptive statistical baselines, multi-signal correlation, path analysis, and explainable machine learning to identify and explain network failures.

Rather than functioning as an Intrusion Detection System (IDS), generic ping monitor, or student toy dashboard, Network Autopsy is designed as an **evidence-driven observability platform** suitable for demonstration to university professors and as a serious engineering prototype.

The primary user interface immediately answers five critical questions:
1. **Is my network OK?** (Overall health state: Healthy, Degraded, Critical, with explainable score).
2. **What is wrong?** (Plain-language symptom translation and user-impact summary).
3. **Where is the problem?** (Interactive hop-by-hop path attribution distinguishing local LAN from transit ISP).
4. **Why does the system think that?** (Corroborated evidence bullet points, agreement count, and rejected alternative hypotheses).
5. **What should I do next?** (Actionable remediation guidance).

At the same time, the platform features a **Technical View (Professor Mode)** toggle that reveals raw feature vectors, mathematical baseline bounds, rule firing conditions, hop confidence calculations, and Decision Tree probabilities.

---

## 2. Problem Statement & Motivation

Small-office, home, and academic lab networks frequently suffer from silent, compound failures:
- **Bufferbloat & Gateway Congestion**: Large queuing buffers causing severe latency spikes during uploads/downloads.
- **Traceroute Misattribution**: Standard tools blaming intermediate transit routers that rate-limit ICMP TTL-Exceeded packets, even when data traffic is forwarded at line rate.
- **Single-Metric False Alarms**: Alerts triggered merely because ping latency exceeded an arbitrary static threshold (e.g. `> 50ms`), ignoring network-specific operational norms.
- **Disconnected Diagnostic Silos**: Requiring operators to manually piece together `ping`, `traceroute`, `tcpdump`, and web application logs.
- **Academic Synthetic Fallacies**: Research prototypes claiming "perfect accuracy" tested only on artificial in-memory arrays without testing against real, degraded network sockets.

Network Autopsy unifies active probing, passive packet sniffing, adaptive baselines, and multi-signal evidence fusion into a single coherent system.

---

## 3. Architecture & Operational Modes

To prevent misleading claims, Network Autopsy explicitly distinguishes **Local Network Monitoring** from **Cloud Demonstration**:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                    MODE A — LOCAL NETWORK AGENT (GENUINE LAN)                │
│  Runs on: Linux, WSL2, Windows                                               │
│  • Active Probes: ICMP, Traceroute, TCP Handshake, DNS, HTTP                 │
│  • Passive Sniffer: TCP Retransmissions, Duplicate ACKs, Checksum Errors     │
│  • Local Safe Socket Proxy: ControlledNetworkTarget (Port 8085)              │
│  • Real Telemetry Label: [● LOCAL NETWORK AGENT]                             │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    MODE B — CLOUD DEMO (RENDER DEPLOYMENT)                   │
│  Hosted at: https://network-autopsy.onrender.com/                            │
│  • Controlled cloud container environment                                    │
│  • TCP ping transport fallback when container ICMP echo is blocked           │
│  • Honest Telemetry Label: [☁️ CLOUD DEMO]                                   │
│  • Never deceptively claims to monitor the browser visitor's personal LAN    │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    MODE C — CONTROLLED DEMONSTRATION MODE                    │
│  • Deterministic fault scenario simulation for professor demonstrations       │
│  • Honest Telemetry Label: [⚡ DEMO MODE]                                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Global Status Model
The system explicitly tracks and displays its operational lifecycle state:
`STARTING` ➔ `CONNECTING` ➔ `COLLECTING` ➔ `WARMING_BASELINE` ➔ `MONITORING` ➔ `DEGRADED` ➔ `INCIDENT_ACTIVE` ➔ `RECOVERING` ➔ `STALE_DATA` ➔ `DEMO_MODE` ➔ `CLOUD_DEMO` ➔ `LOCAL_AGENT`.

The UI **never displays "LIVE NETWORK"** unless verified telemetry is arriving from a local or connected network agent.

---

## 4. End-to-End Diagnosis Pipeline

```
                                  NETWORK ENVIRONMENT
                                           │
                        ┌──────────────────┴──────────────────┐
                        │                                     │
               Active Probes (L3–L7)                 Passive Packet Sniffer (L2–L4)
               • ICMP Gateway & WAN Ping             • TCP Retransmissions
               • TTL Traceroute Sequence             • Duplicate ACKs (RFC 5681)
               • TCP Connect Handshake               • TCP RST / FIN Monitor
               • DNS Query Resolution Time           • IP/TCP Checksum Integrity
               • HTTP GET & TTFB Measurement         • Protocol Distribution
                        │                                     │
                        └──────────────────┬──────────────────┘
                                           │ Raw Metrics
                                           ▼
                               METRICS STORAGE (SQLite WAL)
                                           │
                                           ▼
                              WINDOWED FEATURE AGGREGATOR
                           (20-second rolling sliding windows)
                                           │
                                           ▼
                               ADAPTIVE BASELINE LEARNER
                           (EWMA, Running Mean, StdDev, Median)
                                           │
                                           ▼
                               EVIDENCE FUSION ENGINE
                                           │
                  ┌────────────────────────┼────────────────────────┐
                  ▼                        ▼                        ▼
            8-Rule Expert            Hop Confidence            White-Box CART
              Classifier             Scoring Engine             Decision Tree
           (Cause & Impact)       (Multi-Run Hops)          (Independent Check)
                  │                        │                        │
                  └────────────────────────┼────────────────────────┘
                                           │
                                           ▼
                               INCIDENT LIFECYCLE ENGINE
                       DETECTED ➔ CONFIRMED ➔ ONGOING ➔ RESOLVED
                         (Deduplication & Recovery Detection)
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
                USER VIEW (Default)              TECHNICAL VIEW (Professor Mode)
           • "What is happening?"             • Raw 26-parameter feature vectors
           • "Where is the problem?"          • Mathematical baseline bounds
           • "Why?" (Evidence bullet points)  • Hop scoring confidence formulas
           • Actionable remediation           • Decision Tree if-then rule branches
```

---

## 5. Core Algorithmic Subsystems

### 5.1 Adaptive Baseline Learning
Rather than hardcoding static thresholds, the system learns normal operational bounds using **Exponential Moving Averages (EWMA)** and standard deviation ($\sigma$):
- **Warm-Up Phase**: Requires 8+ observation windows before enabling strict statistical deviation checks.
- **Anomalies**: Flagged when observed telemetry deviates by more than $k \times \sigma$ ($k = 3.0$).
- **Update Rate**: Controlled by $\alpha = 0.05$ to adapt to diurnal shifts without absorbing transient failure spikes into normal baselines.

### 5.2 Corroborated Hop Attribution
Traceroute alone cannot prove an intermediate router is faulty:
- Single-hop spikes are capped at "Low" confidence if downstream hops respond normally (distinguishing ICMP rate-limiting from genuine congestion).
- Confidence is upgraded to "High" only when multiple consecutive runs corroborate delay/loss and independent gateway or WAN probes agree.
- Unconfirmed router drops are explicitly labeled `likely region: hop X–Y (unconfirmed)`.

### 5.3 Common-Language Translation & Progressive Disclosure
The system maintains dual representation for every diagnosis:
- **User View**: Plain English, impact-focused, zero unexplained acronyms.
- **Technical View**: OSI layer, exact rule identifier, raw measurements, and ML class probability.

| Failure Mode | User-Centric Explanation | Technical Description | User Experience Impact |
|:---|:---|:---|:---|
| `GATEWAY_CONGESTION` | "Your connection to the local router or Wi-Fi gateway is congested or experiencing packet loss." | First-hop link saturation with elevated RTT and packet drop at gateway / AP interface. | Streaming video may freeze, web pages load slowly, and calls drop frames. |
| `UPSTREAM_ISP_FAULT` | "A problem was detected in the upstream internet provider or intermediate network path." | Transit carrier degradation or core routing bottleneck at intermediate hop segment. | External services respond slowly while your local router connection is working normally. |
| `DNS_FAILURE` | "Your device can reach the internet, but domain-name lookup (DNS) is failing or timing out." | Domain Name System resolution timeout with intact direct IP layer reachability. | Typing website names fails to load, even though direct IP pings succeed. |
| `TARGET_SERVICE_DOWN` | "The destination server or web service is not accepting connections, although network connectivity is working." | TCP port connection refused (RST) or dropped by firewall with normal ICMP echo reachability. | The specific app or website cannot be reached, but other internet sites work fine. |
| `LOSSY_LINK` | "Your connection is experiencing packet loss, congestion, and dropped data transmissions." | Multi-parameter congestion with TCP fast-retransmits and throughput collapse. | Downloads and streaming will feel stuttery or slow due to repeated data retransmissions. |
| `PACKET_INTEGRITY_ERROR` | "Network packets are arriving with corrupted checksum data, indicating transport or cable errors." | IP header and TCP/UDP payload checksum validation failures in passive traffic. | Connections randomly reset, files fail checksum verification, or transfers stall. |
| `ROUTE_FLAP` | "The network path to the destination changed unexpectedly, causing momentary instability." | Dynamic routing table hop mutation (BGP/OSPF route flap or automated link failover). | Brief lag spikes or 1-2 second disconnections while the router selects a new path. |
| `APPLICATION_FAILURE` | "The network connection is working, but the destination web service is returning an error (HTTP 5xx)." | Application-level HTTP 500/502/503 error returned despite successful TCP handshake. | The website displays an internal server error, but your internet connection is healthy. |

### 5.4 Root-Cause Alternatives & Hypothesis Rejection
Every diagnosis dynamically evaluates alternative hypotheses and presents rejection rationales:
- **Primary Hypothesis**: e.g., DNS Failure (95% confidence).
- **Alternative Considered**: Complete network outage (5% probability) ➔ **REJECTED**: Direct IP pings to `8.8.8.8` and `1.1.1.1` succeeded with low latency.
- **Alternative Considered**: Outbound UDP port 53 firewall rule (20% probability) ➔ **PLAUSIBLE**: Firewall drops produce identical resolver timeout symptoms.

---

## 6. Machine Learning Methodology (Zero Temporal Leakage)

To defend architectural choices during examination, 5 distinct diagnostic models are compared:

1. **Static Threshold Baseline**: Fixed heuristic thresholds (fails to adapt across heterogeneous networks).
2. **Expert Rule System**: 8-rule deterministic expert classifier.
3. **CART Decision Tree (Deployed Primary)**: White-box model (`max_depth=6`) providing 100% auditable if-then decision paths exported to `data/decision_tree_rules.txt`.
4. **Random Forest Benchmark**: 100-tree ensemble providing the empirical accuracy upper bound.
5. **Hybrid Fusion**: Multi-tier consensus architecture combining expert rules and Decision Tree verification.

### Preventing Temporal Data Leakage
Standard train/test splits that randomly shuffle rolling time windows cause severe data leakage because adjacent 20-second windows from the same incident are auto-correlated. Network Autopsy strictly enforces **`GroupShuffleSplit` grouped by unique experiment run ID**, ensuring that entire incident episodes are placed exclusively into either the training or testing partition.

---

## 7. Safe Fault Injection Sandbox

To enable safe laboratory testing without risking university or home Wi-Fi interfaces:
- **Loopback Socket Proxy**: Runs `ControlledNetworkTarget` on `127.0.0.1:8085`.
- **Supported Scenarios**: Latency spikes, jitter/bufferbloat, socket packet loss, TCP connection refusal, HTTP 503 errors, DNS timeouts, and routing hops shifts.
- **Safe Mode Protection**: Injections are restricted to the local loopback proxy target. Zero modifications are made to the host's physical network adapter.
- **Automatic Cleanup**: On server shutdown or crash, all proxy delays and faults are automatically reset to clean defaults.

---

## 8. Empirical Validation vs. Synthetic Benchmark

The platform strictly separates real empirical socket experiments from synthetic algorithmic benchmarks. Performance metrics from these distinct evaluations are never combined.

### 8.1 Empirical Validation (Real Degraded OS Sockets)
Executed against genuine degraded OS sockets on `127.0.0.1:8085` using controlled proxy degradation (persisted in `data/real_validation_results.json`):
- **Sample Size**: $n = 10$ controlled socket trials across fault scenarios
- **Anomaly Detection Rate**: 90.0% (9 / 10 trials successfully detected statistical anomaly)
- **Root-Cause Diagnosis Accuracy**: 20.0% (2 / 10 exact rule identification under compound loopback socket symptoms)
- **Fault Localization Accuracy**: 10.0% (1 / 10 exact hop isolation)
- **Recovery Detection Accuracy**: 100.0% (10 / 10 trials verified return to normal baseline following fault clearing)
- **Mean Detection Latency**: 14.31 seconds (median: 14.07s)
- **Mean Recovery Verification Time**: 14.52 seconds

### 8.2 Algorithm Benchmark (Calibrated Synthetic Distributions)
Evaluated against unit test scenario feature distributions across all 9 fault classes (`data/synthetic_validation_results.json`):
- **Sample Size**: $n = 45$ trials (5 trials per fault class)
- **Overall Benchmark Accuracy**: 88.89% (40 / 45 correct)
- **Per-Class F1-Scores**:
  - `DNS_FAILURE`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `UPSTREAM_ISP_FAULT`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `TARGET_SERVICE_DOWN`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `NETWORK_CONGESTION_LOSSY_LINK`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `PACKET_INTEGRITY_ERROR`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `ROUTE_FLAP`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `APPLICATION_LAYER_FAILURE`: 1.00 (Precision: 1.00, Recall: 1.00)
  - `LOCAL_GATEWAY_CONGESTION`: 0.67 (Precision: 0.50, Recall: 1.00)
  - `HEALTHY_NORMAL`: 0.00 (Precision: 0.00, Recall: 0.00)
- **Note on Normal Telemetry**: The expert rule engine exclusively triggers upon statistical anomaly boundary violations ($> 3\sigma$). When telemetry is healthy and normal, no anomaly rules fire, and the platform safely defaults to the established healthy baseline state.

---

## 9. User Interface Design System

The application interface follows a modern light design system:
- **Palette**: `#F8FAFC` background, crisp white cards, `#E2E8F0` subtle borders, `#0F172A` high-contrast typography, `#2563EB` professional blue accent.
- **Typography**: Inter for all user-facing interface text; JetBrains Mono strictly for IP addresses, technical IDs, and logs.
- **Left Sidebar Navigation**: 7 dedicated functional areas:
  1. **Overview**: Hero Health card, User Impact, Current Issue, 6 metric cards, path preview, timeline charts.
  2. **Network Path**: Full horizontal pipeline (`YOU` ➔ `LOCAL GATEWAY` ➔ `INTERNET` ➔ `DESTINATION`) with clickable node drill-down side panel.
  3. **Incidents**: Correlated incident log with status filters and post-mortem autopsy reports.
  4. **Diagnostics**: Manual diagnostic trigger, "Why We Think This" reasoning box, and multi-signal evidence fusion table.
  5. **Test a Problem**: Safe sandbox fault simulation with 1-click Professor Demo shortcuts, 7-stage live stepper, and ground truth outcome verification.
  6. **Reports**: Post-mortem incident archive with browser print and PDF export layout (`@media print`).
  7. **System**: Subsystem readiness matrix, local agent status, and hardware/driver capture transparency notes.

---

## 10. Installation & Setup

### 10.1 Local Setup (Windows, Linux, macOS)
```bash
# 1. Clone repository
git clone https://github.com/Saicharan-Banothu/CN-CBP.git
cd CN-CBP

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch unified platform
python main.py
```
Open **`http://127.0.0.1:8000/`** in any web browser.

### 10.2 WSL2 / Linux Setup
```bash
sudo apt-get update && sudo apt-get install -y libpcap-dev iproute2
pip install -r requirements.txt
python main.py
```

### 10.3 Packet Capture Permissions
- **Windows**: Install [Npcap](https://npcap.com/) with **"WinPcap API-compatible Mode"** enabled for layer-2 packet sniffing. If Npcap is absent, Network Autopsy gracefully falls back to raw socket mode without failing.
- **Linux**: Grant packet capture capabilities to Python without running as full root:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))
  ```

---

## 11. Running Validation Experiments

Execute end-to-end empirical trials against real degraded sockets:
```bash
# Run 1 real trial per scenario against degraded sockets
python sandbox/validation_runner.py --mode real --trials 1

# Run synthetic algorithm benchmark across all 9 fault classes
python sandbox/validation_runner.py --mode synthetic --trials 10
```

---

## 12. Automated Test Suite

Verify system integrity using pytest:
```bash
python -m pytest -v tests/test_engine.py
```

**Test Coverage (7 Passing Unit Tests)**:
1. `test_windowing_aggregation`: Verifies rolling-window feature aggregation correctness.
2. `test_adaptive_baseline_learner`: Verifies warm-up maturity and statistical $3\sigma$ anomaly triggers.
3. `test_rule_engine_rules`: Verifies 8-rule expert classifier firing conditions and translation fields.
4. `test_hop_confidence_scoring`: Verifies traceroute rate-limiting suppression and multi-signal corroboration.
5. `test_incident_deduplication_lifecycle`: Verifies incident key reuse and recovery state machine transitions.
6. `test_safe_fault_proxy_socket_degradation`: Verifies socket proxy delay injection and HTTP 503 responses.
7. `test_ml_leakage_free_split`: Verifies `GroupShuffleSplit` across distinct incident episodes.

---

## 13. Professor Demonstration Walkthrough (Viva Script)

Follow this 5-minute sequence for laboratory or viva evaluation:

1. **Open Overview**: Show the clean light-themed dashboard on `http://127.0.0.1:8000/`. Highlight the **Hero Health Status** (`Healthy 100/100`), **User Impact** summary, and **6 Metric Cards** (Delay, Stability, Loss, DNS, Web, Retransmissions).
2. **Toggle Professor Mode**: Click **Technical View** in the top bar. Point out the sub-text technical drawers revealing raw parameters (`RFC 3393 jitter`, `TTFB`, `UDP 53 query time`). Click **User View** to switch back.
3. **Inspect Network Path**: Navigate to **Network Path** in the sidebar. Click on the **LOCAL GATEWAY** node (`192.168.0.1`). Show the slide-in inspection panel displaying real round-trip delay, 0% loss, and "Why We Think This" bullet points. Close the panel.
4. **Start Controlled Fault Experiment**:
   - Navigate to **Test a Problem**.
   - Click the shortcut button: **⚡ High Packet Loss (30%)**.
   - Click **🧪 Start Test**.
   - Watch the **7-Stage Live Stepper** advance: `Prepare` ➔ `Apply` ➔ `Collect` ➔ `Analyze` ➔ `Diagnose` ➔ `Recover` ➔ `Done`.
5. **Inspect Live Diagnosis**:
   - Return to **Overview** or **Diagnostics**.
   - Observe the health score drop and the current issue alert box activate.
   - Show the **"Why We Think This"** box with independent signal agreement and alternative hypotheses rejected.
6. **Verify Recovery**:
   - Click **🔄 Reset Baseline**.
   - Show the incident transition to `RESOLVED` with verified recovery time.
7. **Inspect Reports & Validation**:
   - Navigate to **Reports** and open the post-mortem incident report.
   - Navigate to **System** and show the verified Subsystem Readiness Matrix.

---

## 14. Academic Honesty & Known Limitations

1. **Hardware Ethernet FCS vs. Software Checksums**: Standard operating system socket APIs (such as Linux raw sockets, AF_PACKET, and Windows Npcap) do not expose physical 4-byte Ethernet Frame Check Sequences (FCS) because hardware network cards automatically validate and strip FCS before frames reach driver memory. Network Autopsy performs software-level verification of 16-bit Internet checksums (RFC 1071) across captured IPv4 headers, TCP segments, and UDP datagrams. The terminology `PACKET_INTEGRITY_ERROR` explicitly reflects this software checksum validation rather than physical-layer hardware CRC visibility.
2. **Intermediate Router Traceroute Granularity**: Intermediate transit routers that rate-limit or drop ICMP TTL-Exceeded packets cannot be definitively proven as the root cause of an end-to-end failure without corroborating end-to-end telemetry. Network Autopsy explicitly tags these as `likely region: hop X–Y (unconfirmed)` and requires independent probe agreement before upgrading confidence to High.
3. **Cloud Demo vs. Physical Network Monitoring**: In public cloud demonstration environments (such as Render), the platform operates in a containerized environment without access to the visitor's local physical LAN. Raw ICMP echo is firewalled by container security policies, requiring transparent TCP transport ping fallbacks. The UI clearly labels this deployment as **`[☁️ CLOUD DEMO]`** and restricts live fault injection to safe loopback proxy simulation. Live local network monitoring requires running the Local Agent on the target machine.
4. **Public Demo Endpoint Protections**: To prevent abuse in public demonstration environments, mutation endpoints (`/api/inject-fault`, `/api/validation/run-experiment`) enforce strict input validation, parameter bounds checking, concurrency locks, cooldown intervals, and automatic post-experiment cleanup guarantees. Arbitrary shell commands and host interface modifications are strictly blocked.
5. **Empirical Dataset Sample Size**: Empirical validation results reflect $n = 10$ controlled socket proxy experiments on loopback interfaces. While these trials prove end-to-end software integration, anomaly detection, and recovery verification, statistical generalization claims are limited by this sample size and are transparently reported alongside the broader $n = 45$ synthetic algorithm benchmark.

---

## 15. Computer Networks Syllabus Mapping

| Syllabus Concept | Implementation in Network Autopsy | Source File |
|:---|:---|:---|
| **OSI Reference Model** | Multi-layer fault isolation across Physical/Data-Link, Network, Transport, and Application layers. | [`engine/rules.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/engine/rules.py) |
| **Error Detection & Checksums** | Software verification of 16-bit Internet checksums (RFC 1071) for IP, TCP, and UDP headers. | [`agent/passive_capture.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/agent/passive_capture.py) |
| **Flow Control & Congestion** | Detection of duplicate ACKs (RFC 5681 Fast Retransmit) and TCP sequence retransmission tracking. | [`agent/passive_capture.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/agent/passive_capture.py) |
| **IPv4 Header & TTL** | TTL-incrementing traceroute probes measuring hop-by-hop round-trip propagation delay. | [`agent/active_probes.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/agent/active_probes.py) |
| **Routing & Path Dynamics** | Route change detection comparing ordered hop IP sequences across consecutive traceroute runs. | [`engine/windowing.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/engine/windowing.py) |
| **Transport Layer Handshakes** | Direct TCP 3-way handshake measurement (SYN ➔ SYN-ACK) and connection refusal (RST) detection. | [`agent/active_probes.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/agent/active_probes.py) |
| **Application Layer Protocols** | Wire-format DNS resolution and raw HTTP/1.1 transaction measurement with TTFB tracking. | [`agent/active_probes.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/agent/active_probes.py) |
| **Network Emulation & Queuing** | Token bucket rate limiting, delay variance simulation, and socket-level packet drop injection. | [`sandbox/local_fault_proxy.py`](file:///c:/Users/sai%20charan/OneDrive/Desktop/CN_CBP/sandbox/local_fault_proxy.py) |

---

## 16. Project Structure

```
CN_CBP/
├── README.md                      # Comprehensive academic & operational documentation
├── requirements.txt               # Pinned Python dependencies
├── config.yaml                    # System configuration parameters
├── main.py                        # Unified runtime orchestrator & entry point
├── render.yaml                    # Render cloud deployment specification
├── run.sh                         # Unix startup script
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
│   ├── rules.py                   # 8-rule expert root-cause diagnosis classifier & translations
│   ├── hop_confidence.py          # Multi-run hop attribution confidence scorer
│   ├── ml_classifier.py           # 5-model ML comparison & leakage-free group evaluation
│   └── report_generator.py        # Incident lifecycle manager & post-mortem report generator
├── sandbox/
│   ├── fault_injection.py         # SafeFaultController with safe mode & dry-run protections
│   ├── local_fault_proxy.py       # ControlledNetworkTarget socket proxy (port 8085)
│   ├── service_killer.py          # Controlled DNS and HTTP service failure simulators
│   ├── route_flap_sim.py          # Route oscillation simulator
│   └── validation_runner.py       # End-to-end empirical and synthetic experiment runner
├── webapp/
│   ├── server.py                  # FastAPI REST endpoints, status API, and static file mount
│   ├── static/
│   │   ├── dashboard.html         # 7-section professional light-themed dashboard
│   │   ├── dashboard.js           # Centralized state controller, dynamic topology & Chart.js
│   │   └── style.css              # Observability light design system & CSS tokens
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

## 17. License & Credits

Created as a B.Tech Computer Networks Capstone Project by **Sai Charan Banothu**.  
Licensed under the MIT License.
