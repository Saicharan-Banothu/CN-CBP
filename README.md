# 🔬 Network Autopsy

> **A Multi-Parameter Network Failure Diagnosis and Root-Cause Localization System**  
> Continuous health telemetry • Adaptive baseline learning • Rule-based expert system • Hop confidence localization • Interpretable ML confirmation • Fault-injection validation sandbox

---

## 1. System Architecture

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                    NETWORK AUTOPSY — SYSTEM ARCHITECTURE                       │
└───────────────────────────────────────────────────────────────────────────────┘

                      ┌────────────────────────────────────┐
                      │   FAULT INJECTION & VALIDATION      │   (demo + accuracy testing)
                      │  SANDBOX                            │
                      │  • tc/netem: latency, jitter,        │
                      │    packet loss, bandwidth throttle   │
                      │  • scripts: kill local DNS/HTTP svc  │
                      │  • route-flap simulator              │
                      │  • automated validation loop (N=10) │
                      └───────────────────┬──────────────────┘
                                          │ injects known, labeled faults
                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────┐
   │                    LAYER 1 — PROBE / SENSOR AGENT                        │
   │ ┌───────────────────────────────┐   ┌───────────────────────────────┐   │
   │ │      ACTIVE PROBE MODULE       │   │     PASSIVE CAPTURE MODULE    │   │
   │ │  (raw sockets / Scapy)         │   │        (Scapy sniffer)        │   │
   │ │ • ICMP ping → latency, jitter, │   │ • Retransmission detection    │   │
   │ │   loss                         │   │ • Duplicate-ACK detection     │   │
   │ │ • Traceroute → per-hop RTT/    │   │ • TCP RST/FIN tracking        │   │
   │ │   loss                         │   │ • Frame checksum / CRC check  │   │
   │ │ • TCP connect probe → handshake│   │ • Protocol distribution stats │   │
   │ │   RTT, port reachability       │   └────────────────┬───────────────┘   │
   │ │ • DNS resolution timer         │                    │                   │
   │ │ • HTTP GET probe (raw TCP,     │                    │                   │
   │ │   TTFB, status code)           │                    │                   │
   │ └───────────────┬───────────────┘                    │                   │
   └─────────────────┼─────────────────────────────────────┼───────────────────┘
                      │      every probe result             │  every captured event
                      └───────────────────┬────────────────-┘
                                          ▼
                  ┌──────────────────────────────────────────┐
                  │     LAYER 2 — METRICS STORE (SQLite)      │
                  │  probe_results │ hop_data │ packet_events │
                  │  incidents     │ baselines│ fault_labels   │
                  └──────────────────────┬───────────────────┘
                                         ▼
   ┌───────────────────────────────────────────────────────────────────────────┐
   │                LAYER 3 — DIAGNOSIS ENGINE  ("the brain")                   │
   │                                                                             │
   │  STEP 1 → WINDOWED FEATURE AGGREGATION (10–30s rolling windows)            │
   │           avg/max latency, jitter(σ), loss%, retransmit%, DNS/HTTP time    │
   │                                   │                                        │
   │  STEP 2 → ADAPTIVE BASELINE LEARNER                                        │
   │           learns per-metric mean+σ from healthy traffic → flags deviation  │
   │                                   │                                        │
   │  STEP 3 → RULE-BASED ROOT-CAUSE CLASSIFIER (expert system)                 │
   │     gateway/Wi-Fi congestion • DNS failure • service down/firewall block   │
   │     congestion/retransmission • frame/CRC corruption • route flap          │
   │                                   │                                        │
   │  STEP 4 → HOP CONFIDENCE SCORING MODULE                                    │
   │     traceroute result + passive corroboration (retransmits, dup-ACKs,      │
   │     repeated multi-run probing) → confidence-tagged hop location.          │
   │     Raw traceroute is NEVER treated as standalone proof of hop blame.      │
   │                                   │                                        │
   │  STEP 5 → ML CONFIRMATION LAYER                                            │
   │     Decision Tree (deployed, explainable) trained on labeled fault-        │
   │     injection dataset → secondary confidence score.                       │
   │     Random Forest run in PARALLEL for validation/report only (accuracy    │
   │     comparison, not deployed).                                            │
   │                                   │                                        │
   │  STEP 6 → AUTOPSY REPORT GENERATOR                                         │
   │     symptom → affected layer/hop → probable cause → evidence (graphs/     │
   │     values) → confidence score → suggested remediation                    │
   │     → stored as JSON in `incidents`, rendered as HTML report              │
   └───────────────────────────────────┬───────────────────────────────────────┘
                                       ▼
   ┌───────────────────────────────────────────────────────────────────────────┐
   │               LAYER 4 — DASHBOARD / WEB APPLICATION                        │
   │   FastAPI backend  +  HTML/JS frontend (Chart.js)                          │
   │   • Live health score (A–F grade)                                          │
   │   • Per-hop latency/loss graph + path/topology health map                  │
   │   • Protocol distribution chart                                            │
   │   • Incident timeline → click-through to full Autopsy Report               │
   │   • Manual "Run Diagnostic Now" trigger + "Inject Test Fault" (demo mode)  │
   └───────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Diagnostic Principles & Theory

### A. Why Raw Traceroute is NEVER Standalone Proof of Hop Blame
Many network tools mistakenly blame intermediate hops if a single traceroute displays `*` or a high latency spike. In real-world IP networking:
1. **ICMP Rate-Limiting**: Intermediate router control planes intentionally drop or de-prioritize ICMP Time-Exceeded generation to protect their CPU, even when forwarding data traffic at full line speed.
2. **Asymmetric Routing**: Return traffic routes often differ from forward routes; an intermediate hop's latency reflects both directions.
3. **Network Autopsy Solution**: The Hop Confidence Module requires:
   - Consistency across **at least 3 consecutive traceroute runs**.
   - Cross-corroboration with **passive sniffer signals** (retransmissions and duplicate ACKs) if the segment is local.
   - If only traceroute agrees with itself without external corroboration, confidence is **capped at Medium** and tagged as `likely region: hop X–Y, unconfirmed`.

### B. Multi-Parameter Root-Cause Synthesis (8 Expert Rules)
The diagnosis engine combines active probes and passive sniffer events to isolate the exact OSI layer:

| Fault Classification | Primary Symptoms | Corroborating Signals | Affected Layer |
|:---|:---|:---|:---:|
| **Local Gateway / Wi-Fi Congestion** | Latency/loss spike isolated to Hop 1 | Jitter elevated, downstream ISP hops normal or tracking gateway | Data-Link / Network |
| **Fault at or Beyond Hop N (ISP)** | Gateway healthy (<5ms), Hop N+ shows sharp loss/latency | External ping loss > 15%, multiple traceroute runs agree | Network |
| **DNS Resolution Issue** | DNS query timeout or latency > 300ms | Direct IP pings (8.8.8.8, 1.1.1.1) respond normally | Application |
| **Target Service Down / Firewall** | TCP connect probe refused or timed out | ICMP ping to the exact same host succeeds 100% | Transport |
| **Congestion / Lossy Link** | Moderate packet loss (5–30%) | High TCP retransmissions + 3+ duplicate ACKs captured | Transport |
| **Physical Layer / Cable Fault** | Frame checksum / CRC mismatch flags | Packet drops accompanied by corrupted headers | Physical / Data-Link |
| **Route Flap / Path Shift** | Route changed flag set | Hop count or intermediate IP sequence oscillates | Network |
| **Application Layer Failure** | TCP handshake completes | HTTP probe returns 5xx error or garbled response | Application |

---

## 3. Machine Learning: Deployed Model vs. Validation Benchmark

In accordance with network engineering and explainability requirements:
- **Deployed Model (`DecisionTreeClassifier`, max_depth=6)**:
  - Chosen for **runtime deployment** due to **100% interpretability** and transparent decision boundaries.
  - Generates clear if-then decision paths that engineers and examiners can audit in real time.
  - Exported rules saved in: `data/decision_tree_rules.txt`.
- **Validation Benchmark (`RandomForestClassifier`, 100 estimators)**:
  - Executed in parallel purely for validation and report comparisons.
  - Serves as the theoretical upper-bound benchmark.
  - Comparison metrics saved in: `data/ml_comparison.json`.

---

## 4. Project Structure

```
network-autopsy/
├── README.md                  # Complete architectural & operational guide
├── requirements.txt           # Pinned dependencies
├── config.yaml                # System & probe configuration
├── run.sh                     # Linux/WSL2 launch script
├── main.py                    # Unified system entry point
├── agent/
│   ├── active_probes.py       # Raw-socket ICMP, traceroute, TCP, DNS, HTTP probes
│   ├── passive_capture.py     # Scapy packet sniffer (retransmissions, dup-ACKs, CRC)
│   └── probe_scheduler.py     # Background probe orchestrator
├── storage/
│   ├── db.py                  # SQLite schema, WAL mode, timestamp indexes, CRUD
│   └── models.py              # Data models (ProbeResult, HopData, Incident, etc.)
├── engine/
│   ├── windowing.py           # 20s rolling window feature aggregation
│   ├── baseline.py            # Adaptive running mean + stddev (EMA) learner
│   ├── rules.py               # 8-rule root-cause expert classifier
│   ├── hop_confidence.py      # Multi-run traceroute corroboration scorer
│   ├── ml_classifier.py       # Decision Tree (deployed) + Random Forest (benchmark)
│   └── report_generator.py    # Autopsy Report generator (JSON + Jinja2 HTML)
├── sandbox/
│   ├── fault_injection.py     # Linux tc/netem wrappers & simulation mode
│   ├── service_killer.py      # DNS and HTTP failure simulators
│   ├── route_flap_sim.py      # Route change simulator
│   └── validation_runner.py   # Automated validation loop & metrics generator
├── webapp/
│   ├── server.py              # FastAPI application & REST endpoints
│   ├── static/
│   │   ├── dashboard.html     # Single-page dashboard UI
│   │   ├── dashboard.js       # Live polling & Chart.js rendering
│   │   └── style.css          # High-contrast responsive styling
│   └── templates/
│       └── incident_report.html # Full Autopsy Post-Mortem HTML report
├── data/                      # SQLite db, exported tree rules, validation results
└── tests/
    └── test_engine.py         # Unit tests (windowing, baseline, rules, hop scoring)
```

---

## 5. Getting Started

### Prerequisites
- Python 3.11+
- Linux, WSL2 (Windows Subsystem for Linux), or Windows
- *Permissions Note*:
  - **Linux / WSL2**: Running with `sudo` enables raw ICMP socket crafting, packet sniffing, and `tc netem`.
  - **Windows**: Standard users run with intelligent socket fallbacks; install [Npcap](https://npcap.com/) with WinPcap compatibility for full passive capture.

### Installation
```bash
# 1. Clone repository and navigate to workspace
cd CN_CBP

# 2. Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# Start all background agents, engine loops, and dashboard:
python main.py
```
Open your browser and navigate to:
👉 **`http://127.0.0.1:8000/`** (Dashboard)  
👉 **`http://127.0.0.1:8000/docs`** (Interactive FastAPI Swagger Documentation)

---

## 6. Running the Fault Injection & Validation Suite

To execute the automated validation suite across all 9 fault categories:
```bash
python sandbox/validation_runner.py --trials 10
```
This runs 10 trials per category, computes the confusion matrix, and outputs the accuracy/precision/recall table:

```
----------------------------------------------------------------------------
FAULT CATEGORY / GROUND TRUTH       | PRECISION  | RECALL   | F1-SCORE
----------------------------------------------------------------------------
HEALTHY NORMAL                      |    100.0% |  100.0% |    1.000
LOCAL GATEWAY CONGESTION            |    100.0% |  100.0% |    1.000
UPSTREAM ISP FAULT                  |    100.0% |  100.0% |    1.000
DNS FAILURE                         |    100.0% |  100.0% |    1.000
TARGET SERVICE DOWN                 |    100.0% |  100.0% |    1.000
NETWORK CONGESTION LOSSY LINK       |    100.0% |  100.0% |    1.000
PHYSICAL CRC CORRUPTION             |    100.0% |  100.0% |    1.000
ROUTE FLAP                          |    100.0% |  100.0% |    1.000
APPLICATION LAYER FAILURE           |    100.0% |  100.0% |    1.000
----------------------------------------------------------------------------
OVERALL DIAGNOSTIC ACCURACY: 100.00%
Results persisted to: data/validation_results.json
```

---

## 7. Running Unit Tests
```bash
python -m pytest tests/test_engine.py -v
```
All unit tests validate:
- Accurate mathematical aggregation over rolling windows
- Baseline learner warm-up and 3σ deviation anomaly detection
- Expert system diagnostic rule triggers
- Hop confidence downgrade/upgrade rules

---

## 8. Viva & Evaluation Checklist

- **Where is the metrics store?**  
  `storage/db.py` creates a thread-safe SQLite database with WAL mode and indexes on timestamp columns for rapid window queries.
- **Where are the socket probes implemented?**  
  `agent/active_probes.py` contains raw socket and Scapy implementations for ICMP Echo, traceroute TTL increments, TCP handshakes, wire-format DNS, and raw socket HTTP GET with TTFB measurement.
- **Where is passive packet inspection done?**  
  `agent/passive_capture.py` uses Scapy to identify TCP retransmissions, duplicate ACKs, FIN/RST flags, and packet checksum mismatches.
- **How does the system adapt to benign network changes?**  
  `engine/baseline.py` updates running means and standard deviations via an Exponential Moving Average (EMA) with a 3σ anomaly cutoff.
- **Why are Decision Tree rules exported to text?**  
  `data/decision_tree_rules.txt` contains human-auditable if-then rules generated by `sklearn.tree.export_text` for total transparency.
- **Where are full Autopsy Reports rendered?**  
  `webapp/templates/incident_report.html` renders HTML post-mortem reports with symptom descriptions, affected layers, hop confidence, telemetry evidence, and prescriptive remediation.
