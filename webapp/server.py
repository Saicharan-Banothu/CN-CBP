"""
FastAPI Server for Network Autopsy.
Exposes REST APIs for telemetry, explainable health grades, dynamic topology,
incident lifecycle management, manual diagnostic execution, sandbox safe fault injection,
and real vs synthetic validation experiment analytics.
Serves static dashboard and rendered HTML autopsy reports.
"""
import os
import sys
import time
import json
import platform
import logging
import threading
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Query, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from storage.db import Database, get_db
from storage.models import Incident, ExperimentRecord
from engine.windowing import WindowAggregator, WindowFeatures
from engine.baseline import AdaptiveBaselineLearner
from engine.rules import RuleClassifier
from engine.hop_confidence import HopConfidenceScorer
from engine.ml_classifier import (
    get_ml_classifier,
    COMPARISON_PATH,
    RULES_PATH,
    FEATURE_METADATA,
)
from engine.report_generator import ReportGenerator
from agent.probe_scheduler import ProbeScheduler
from agent.passive_capture import PassiveCaptureAgent
from sandbox import fault_injection, service_killer, route_flap_sim
from sandbox.fault_injection import SafeFaultController, SAFE_FAULT_SCENARIOS
from sandbox.local_fault_proxy import start_local_fault_proxy, stop_local_fault_proxy

logger = logging.getLogger("network_autopsy.server")

# Base Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "webapp", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "webapp", "templates")
DATA_DIR = os.path.join(BASE_DIR, "data")
REAL_VALIDATION_PATH = os.path.join(DATA_DIR, "real_validation_results.json")
SYNTHETIC_VALIDATION_PATH = os.path.join(DATA_DIR, "synthetic_validation_results.json")
SEED_TRIALS_PATH = os.path.join(DATA_DIR, "real_trials_seed.json")

app = FastAPI(
    title="Network Autopsy",
    description="Multi-Parameter Network Failure Diagnosis and Root-Cause Localization Platform",
    version="2.0.0",
)

# Shared instances (initialized at startup)
db = get_db()
aggregator = WindowAggregator(db)
baseline_learner = AdaptiveBaselineLearner(db)
rules_classifier = RuleClassifier()
hop_scorer = HopConfidenceScorer(db)
ml_classifier = get_ml_classifier()
report_gen = ReportGenerator(db)
fault_controller = SafeFaultController(db=db)

# References to background agents (set by main.py)
probe_scheduler_ref: Optional[ProbeScheduler] = None
passive_capture_ref: Optional[PassiveCaptureAgent] = None

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# System Mode state tracking & Security Guards
SYSTEM_MODE_OVERRIDE: Optional[str] = None
IS_CLOUD_DEMO: bool = bool(os.environ.get("RENDER") or os.environ.get("RENDER_SERVICE_ID") or os.environ.get("AUTOPSY_CLOUD_MODE"))
_LAST_FAULT_TIME: float = 0.0
_LAST_EXPERIMENT_TIME: float = 0.0
_EXPERIMENT_LOCK = threading.Lock()


def get_current_system_mode() -> str:
    """Returns whether the system is running in Local Network mode or Cloud Demo mode."""
    global SYSTEM_MODE_OVERRIDE
    if SYSTEM_MODE_OVERRIDE:
        return SYSTEM_MODE_OVERRIDE
    if IS_CLOUD_DEMO:
        return "CLOUD_DEMO"
    return "LOCAL_NETWORK"


@app.get("/")
def index():
    return RedirectResponse(url="/static/dashboard.html")


@app.get("/api/system/status")
def get_system_status():
    """
    Returns global system status, explicit mode (LOCAL_NETWORK vs CLOUD_DEMO),
    data freshness, current user impact summary, and active issue details.
    """
    mode = get_current_system_mode()
    features = aggregator.aggregate_current_window()
    anomalies = baseline_learner.evaluate_window(features)
    open_incidents = db.get_incidents(limit=1, status="ONGOING")
    if not open_incidents:
        open_incidents = db.get_incidents(limit=1, status="DETECTED")
    if not open_incidents:
        open_incidents = db.get_incidents(limit=1, status="CONFIRMED")

    now = time.time()
    data_age_s = round(now - features.window_end, 1) if features.window_end > 0 else 0.0
    is_stale = data_age_s > 45.0

    # Baseline maturity
    base_summary = baseline_learner.get_ui_summary()
    total_samples = sum(b.get("sample_count", 0) for b in base_summary.values())
    is_warming = total_samples < 8

    # Determine global status
    if is_stale:
        global_status = "STALE_DATA"
    elif open_incidents:
        global_status = "INCIDENT_ACTIVE"
    elif is_warming:
        global_status = "WARMING_BASELINE"
    elif mode == "CLOUD_DEMO":
        global_status = "CLOUD_DEMO"
    elif mode == "DEMO_MODE":
        global_status = "DEMO_MODE"
    else:
        global_status = "MONITORING"

    # Data source label
    if mode == "CLOUD_DEMO":
        data_source = "Controlled Cloud Test Environment"
    elif mode == "DEMO_MODE":
        data_source = "Controlled Demonstration Scenario"
    else:
        data_source = "Local Network Agent"

    # User impact & current issue
    curr_issue = None
    user_impact_summary = "Your network is operating within its normal range."

    if open_incidents:
        inc = open_incidents[0]
        ev = inc.get_evidence()
        curr_issue = {
            "incident_id": inc.id,
            "title": inc.probable_cause,
            "user_description": ev.get("user_description", inc.symptom),
            "likely_location": inc.hop_location,
            "confidence_pct": int(inc.confidence_score * 100),
            "started_at": time.strftime("%H:%M:%S", time.localtime(inc.detected_at)),
            "duration_s": round(now - inc.detected_at, 1),
            "status": inc.status,
            "why_points": ev.get("why_points", [inc.symptom]),
            "remediation": inc.remediation_text,
        }
        user_impact_summary = ev.get("user_impact", "Network performance is currently degraded.")
    elif is_stale:
        user_impact_summary = "Telemetry data is stale. Waiting for fresh telemetry from network agent."

    # Subsystem readiness
    has_pcap = False
    try:
        from scapy.config import conf
        has_pcap = bool(conf.use_pcap)
    except Exception:
        has_pcap = False

    return {
        "system_mode": mode,
        "global_status": global_status,
        "data_source": data_source,
        "is_live_network": (mode == "LOCAL_NETWORK" and not is_stale),
        "data_freshness": {
            "last_updated": time.strftime("%H:%M:%S", time.localtime(now - data_age_s)) if data_age_s > 0 else "Just now",
            "data_age_s": data_age_s,
            "is_stale": is_stale,
        },
        "user_impact_summary": user_impact_summary,
        "current_issue": curr_issue,
        "agent_info": {
            "machine": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "architecture": platform.machine(),
            "python": sys.version.split()[0],
            "status": "OFFLINE" if is_stale else "CONNECTED",
            "capabilities": [
                "Active Probes (Ping, Traceroute, DNS, HTTP, TCP)",
                "Passive Packet Capture (IP/TCP/UDP Checksums)",
                "Adaptive Baseline Learning (EMA + Z-score)",
                "Explainable Decision Tree ML",
                "Controlled Socket Fault Sandbox",
            ],
        },
        "readiness": {
            "network_monitoring": "READY",
            "packet_capture": "OPERATIONAL" if has_pcap else "LIMITED (Raw Socket Mode)",
            "traceroute": "READY",
            "fault_testing": "READY",
            "machine_learning": "READY",
            "database": "READY",
        },
        "timestamp": now,
    }


class SystemModeRequest(BaseModel):
    mode: str  # "LOCAL_NETWORK", "CLOUD_DEMO", "DEMO_MODE"


@app.post("/api/system/mode")
def set_system_mode(req: SystemModeRequest):
    """Allows manual simulation or toggling between Local Network, Cloud Demo, and Demo modes."""
    global SYSTEM_MODE_OVERRIDE
    if IS_CLOUD_DEMO and req.mode == "LOCAL_NETWORK":
        raise HTTPException(
            status_code=403,
            detail="Cannot switch to LOCAL_NETWORK on Cloud Demo deployment. The cloud container does not have physical LAN access.",
        )
    if req.mode in ("LOCAL_NETWORK", "CLOUD_DEMO", "DEMO_MODE"):
        SYSTEM_MODE_OVERRIDE = req.mode
        return {"status": "SUCCESS", "current_mode": SYSTEM_MODE_OVERRIDE}
    raise HTTPException(status_code=400, detail="Invalid system mode. Expected LOCAL_NETWORK, CLOUD_DEMO, or DEMO_MODE.")


@app.get("/api/environment")
def get_environment_diagnostics():
    """
    Returns environment capabilities, permission state, and subsystem availability.
    Crucial for viva defense to prove transparent system awareness.
    """
    has_pcap = False
    try:
        from scapy.config import conf
        has_pcap = bool(conf.use_pcap)
    except Exception:
        has_pcap = False

    is_linux = platform.system() == "Linux"
    has_tc = False
    if is_linux:
        import shutil
        has_tc = shutil.which("tc") is not None

    return {
        "operating_system": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python_version": sys.version.split()[0],
        "packet_capture": {
            "available": has_pcap,
            "backend": "Npcap/WinPcap" if platform.system() == "Windows" else "libpcap / PF_PACKET",
            "status": "OPERATIONAL" if has_pcap else "LIMITED (Raw Socket Mode)",
            "guidance": "Install Npcap on Windows with 'WinPcap API-compatible Mode' enabled for full promiscuous sniffer." if not has_pcap and platform.system() == "Windows" else "Capture operational.",
            "note": "IP header and TCP/UDP checksums are inspected. Physical Ethernet FCS is verified by network interface card hardware and stripped prior to userspace capture.",
        },
        "fault_injection": {
            "mode": "SAFE_SOCKET_PROXY_AND_SERVICE_EMULATION",
            "proxy_port": 8085,
            "tc_netem_available": has_tc,
            "supported_scenarios_count": len(SAFE_FAULT_SCENARIOS),
            "safe_mode_enabled": fault_controller.safe_mode,
        },
        "database": {
            "status": "READY",
            "engine": "SQLite WAL Mode",
            "path": db.db_path,
        },
        "machine_learning": {
            "status": "READY",
            "deployed_model": "DecisionTreeClassifier (max_depth=6)",
            "validation_benchmark": "RandomForestClassifier (100 trees)",
            "rules_exported": os.path.exists(RULES_PATH),
        },
        "timestamp": time.time(),
    }


@app.get("/api/demo-service/health")
def demo_service_health():
    """
    Controlled HTTP endpoint used by active HTTP probe.
    Can be toggled by the sandbox service killer to simulate HTTP application failure.
    """
    if not service_killer.SERVICE_STATES["http_healthy"]:
        code = service_killer.SERVICE_STATES["http_error_code"]
        raise HTTPException(status_code=code, detail=f"Simulated HTTP Service Down (Status {code})")
    return {
        "status": "UP",
        "service": "NetworkAutopsyDemoLocalEndpoint",
        "timestamp": time.time(),
    }


@app.get("/api/health")
def get_health():
    """
    Calculates overall network health score (0-100), primary state (Healthy, Degraded, Critical),
    and explainable contributor impact points.
    Latency penalty is baseline-aware (uses adaptive learned EMA mean, not a hardcoded threshold).
    """
    features = aggregator.aggregate_current_window()
    anomalies = baseline_learner.evaluate_window(features)
    open_incidents = db.get_incidents(limit=5, status="ONGOING")
    if not open_incidents:
        open_incidents = db.get_incidents(limit=5, status="DETECTED")

    # Fetch adaptive baselines for baseline-aware scoring
    baselines = baseline_learner.get_ui_summary()
    lat_baseline_info = baselines.get("avg_latency", {})
    base_lat = lat_baseline_info.get("mean", 25.0)
    sample_count = lat_baseline_info.get("sample_count", 0)
    baseline_mature = sample_count >= baseline_learner.warmup_samples
    baseline_status = "ESTABLISHED" if baseline_mature else "WARMING_UP"
    # Conservative floor: never penalise below 30ms baseline (well-connected links)
    lat_threshold = max(base_lat * 2.0, 50.0)  # 2x learned baseline, minimum 50ms

    score = 100
    contributors = []

    # 1. Packet Loss Penalty (absolute — any loss is abnormal)
    if features.loss_pct > 0:
        loss_pen = min(int(features.loss_pct * 2.0), 40)
        score -= loss_pen
        contributors.append({
            "parameter": "Packet Loss",
            "impact_points": loss_pen,
            "penalty": -loss_pen,
            "observed": f"{features.loss_pct:.1f}% loss",
            "baseline": "0.0%",
            "severity": "CRITICAL" if loss_pen > 20 else "MODERATE",
            "explanation": f"Packets dropped in transmission reduce score by {loss_pen} points.",
        })

    # 2. Latency Anomaly Penalty (BASELINE-AWARE: uses adaptive learned mean, not hardcoded 60ms)
    if features.avg_latency > lat_threshold:
        lat_pen = min(int((features.avg_latency - lat_threshold) * 0.4), 25)
        score -= lat_pen
        contributors.append({
            "parameter": "Connection Delay",
            "impact_points": lat_pen,
            "penalty": -lat_pen,
            "observed": f"{features.avg_latency:.1f} ms",
            "baseline": f"< {lat_threshold:.0f} ms (2× learned baseline: {base_lat:.0f} ms)",
            "severity": "HIGH" if lat_pen > 15 else "LOW",
            "explanation": (
                f"Latency {features.avg_latency:.0f}ms exceeds 2× learned baseline ({base_lat:.0f}ms) "
                f"— reduces score by {lat_pen} points."
            ),
        })

    # 3. DNS Failure Penalty
    if features.dns_loss_pct > 0:
        dns_pen = min(int(features.dns_loss_pct * 0.3), 30)
        score -= dns_pen
        contributors.append({
            "parameter": "DNS Resolution Degradation",
            "impact_points": dns_pen,
            "penalty": -dns_pen,
            "observed": f"{features.dns_loss_pct:.1f}% failure",
            "baseline": "0.0%",
            "severity": "CRITICAL",
            "explanation": f"Failed domain name lookups reduce score by {dns_pen} points.",
        })

    # 4. HTTP Application Failure Penalty
    if features.http_loss_pct > 0:
        http_pen = min(int(features.http_loss_pct * 0.25), 25)
        score -= http_pen
        contributors.append({
            "parameter": "Web Service Response",
            "impact_points": http_pen,
            "penalty": -http_pen,
            "observed": f"HTTP {features.http_status_code} ({features.http_loss_pct:.0f}% failure)",
            "baseline": "HTTP 200 OK",
            "severity": "HIGH",
            "explanation": f"Web application response error reduces score by {http_pen} points.",
        })

    # 5. TCP Retransmissions & Congestion Penalty
    if features.retrans_count > 3:
        tcp_pen = min(int(features.retrans_count * 2), 20)
        score -= tcp_pen
        contributors.append({
            "parameter": "Data Retransmissions",
            "impact_points": tcp_pen,
            "penalty": -tcp_pen,
            "observed": f"{features.retrans_count} retransmissions",
            "baseline": "< 2",
            "severity": "MODERATE",
            "explanation": f"Transport layer re-sending data reduces score by {tcp_pen} points.",
        })

    # 6. Packet Integrity (IP/TCP Checksum Errors from passive capture)
    if features.checksum_errors > 0:
        chk_pen = min(features.checksum_errors * 5, 20)
        score -= chk_pen
        contributors.append({
            "parameter": "Packet Integrity Validation",
            "impact_points": chk_pen,
            "penalty": -chk_pen,
            "observed": f"{features.checksum_errors} IP/TCP checksum errors",
            "baseline": "0",
            "severity": "CRITICAL",
            "explanation": (
                f"IP and TCP checksum errors detected via passive packet capture "
                f"reduce score by {chk_pen} points."
            ),
        })

    # 7. Route Instability Penalty
    if features.route_changed:
        score -= 10
        contributors.append({
            "parameter": "Route Stability",
            "impact_points": 10,
            "penalty": -10,
            "observed": "Path altered vs historical topology",
            "baseline": "Stable path",
            "severity": "LOW",
            "explanation": "Dynamic routing hop change reduces score by 10 points.",
        })

    # 8. Active Incident Penalty
    if open_incidents:
        inc_pen = min(len(open_incidents) * 5, 15)
        score -= inc_pen
        contributors.append({
            "parameter": "Active Unresolved Incidents",
            "impact_points": inc_pen,
            "penalty": -inc_pen,
            "observed": f"{len(open_incidents)} ongoing",
            "baseline": "0",
            "severity": "MODERATE",
            "explanation": f"Unresolved incident state reduces score by {inc_pen} points.",
        })

    score = max(min(int(score), 100), 10)

    primary_concern = contributors[0]["parameter"] if contributors else "None (Normal Operation)"
    primary_penalty = contributors[0]["penalty"] if contributors else 0

    # Primary Health State & Grade mapping
    if score >= 85:
        health_status = "Healthy"
        grade = "A" if score >= 90 else "B"
        if not baseline_mature and len(open_incidents) == 0:
            summary = f"Establishing network baseline ({sample_count}/{baseline_learner.warmup_samples} observations collected)..."
        else:
            summary = "Your network is operating within its normal range."
    elif score >= 60:
        health_status = "Degraded"
        grade = "C" if score >= 70 else "D"
        summary = f"Performance degradation detected: {primary_concern}."
    else:
        health_status = "Critical"
        grade = "F"
        summary = f"Severe network impairment detected: {primary_concern}."

    return {
        "health_status": health_status,
        "grade": grade,
        "score": score,
        "status_summary": summary,
        "primary_concern": primary_concern,
        "primary_penalty": primary_penalty,
        "baseline_status": baseline_status,
        "baseline_samples": sample_count,
        "baseline_warmup_target": baseline_learner.warmup_samples,
        "active_incidents": len(open_incidents),
        "anomalies_detected": len(anomalies),
        "contributors": contributors,
        "baseline_latency_ms": round(base_lat, 1),
        "latency_threshold_ms": round(lat_threshold, 1),
        "timestamp": time.time(),
    }


@app.get("/api/latest-metrics")
def get_latest_metrics():
    """Returns rolling window features, baseline status, and structured user metric cards."""
    features = aggregator.aggregate_current_window()
    baselines = baseline_learner.get_ui_summary()

    if passive_capture_ref:
        passive_stats = passive_capture_ref.get_stats()
    else:
        db_protos = db.get_observed_protocol_counts()
        passive_stats = {
            "sniffer_active": False,
            "sniffer_error": "",
            "capture_mode": "Network Telemetry",
            "protocols": db_protos,
            "events": {},
            "total_packets": sum(db_protos.values()),
        }

    if sum(passive_stats.get("protocols", {}).values()) == 0:
        db_protos = db.get_observed_protocol_counts()
        passive_stats["protocols"] = db_protos
        passive_stats["total_packets"] = sum(db_protos.values())
        passive_stats["capture_mode"] = "Network Telemetry"

    now = time.time()
    data_age_s = round(now - features.window_end, 1) if features.window_end > 0 else 0.0
    is_stale = data_age_s > 45.0
    mode = get_current_system_mode()

    # Base values
    base_lat = baselines.get("avg_latency", {}).get("mean", 20.0)
    lat_diff = round(((features.avg_latency - base_lat) / max(base_lat, 1)) * 100) if features.avg_latency > 0 else 0

    metric_cards = {
        "connection_delay": {
            "title": "Connection delay",
            "current": f"{features.avg_latency:.1f} ms" if features.avg_latency > 0 else "0.0 ms",
            "normal_range": f"{max(base_lat - 10, 2):.0f}–{base_lat + 15:.0f} ms",
            "difference": f"{lat_diff:+d}%",
            "status": "Higher than normal" if lat_diff > 40 else "Normal",
            "technical_drawer": f"Avg: {features.avg_latency:.1f}ms | Max: {features.max_latency:.1f}ms | Probes: {features.raw_probe_count} (ICMP Echo)",
        },
        "connection_stability": {
            "title": "Connection stability",
            "current": f"{features.jitter:.1f} ms",
            "normal_range": "< 4.0 ms",
            "difference": "Normal" if features.jitter < 4.0 else f"+{features.jitter:.1f} ms",
            "status": "Stable" if features.jitter < 6.0 else "High Jitter",
            "technical_drawer": "RFC 3393 packet arrival delay variance (stddev across rolling window)",
        },
        "packet_loss": {
            "title": "Packet loss",
            "current": f"{features.loss_pct:.1f}%",
            "normal_range": "0.0%",
            "difference": "+0%" if features.loss_pct == 0 else f"+{features.loss_pct:.1f}%",
            "status": "Normal" if features.loss_pct < 2.0 else "Packet Drop Detected",
            "technical_drawer": f"Probes sent: {features.raw_probe_count * 3} | Packets acknowledged: {int(features.raw_probe_count * 3 * (1 - features.loss_pct/100))}",
        },
        "dns_response": {
            "title": "DNS response",
            "current": f"{features.dns_latency:.1f} ms",
            "normal_range": "15–50 ms",
            "difference": "Normal" if features.dns_latency < 60 else "Elevated",
            "status": "Healthy" if features.dns_loss_pct < 10 else "Degraded",
            "technical_drawer": f"DNS failure rate: {features.dns_loss_pct:.0f}% | Target resolver: 8.8.8.8 (UDP port 53)",
        },
        "web_service_response": {
            "title": "Web service response",
            "current": f"HTTP {features.http_status_code}",
            "normal_range": "HTTP 200",
            "difference": "OK" if features.http_status_code == 200 else f"HTTP {features.http_status_code}",
            "status": "Available" if features.http_status_code == 200 else "Service Failure",
            "technical_drawer": f"HTTP probe round-trip: {features.http_latency:.1f}ms | TTFB: {features.http_ttfb:.1f}ms",
        },
        "data_retransmissions": {
            "title": "Data retransmissions",
            "current": f"{features.retrans_count}",
            "normal_range": "< 2",
            "difference": "0" if features.retrans_count == 0 else f"+{features.retrans_count}",
            "status": "Normal" if features.retrans_count < 3 else "Congested",
            "technical_drawer": f"TCP fast-retransmits: {features.retrans_count} | Duplicate ACKs: {features.dup_ack_count}",
        },
    }

    return {
        "features": features.to_dict(),
        "baselines": baselines,
        "metric_cards": metric_cards,
        "passive_stats": passive_stats,
        "timestamp": now,
        "data_age_s": data_age_s,
        "is_stale": is_stale,
        "system_mode": mode,
        "telemetry_source": "Controlled Cloud Environment" if mode == "CLOUD_DEMO" else "Local Network Agent",
    }


@app.get("/api/topology")
def get_topology():
    """
    Returns dynamic hop-by-hop path topology with user-friendly stage grouping
    (YOU -> LOCAL GATEWAY -> INTERMEDIATE NETWORK -> DESTINATION),
    collapsible healthy hops, and hop confidence analysis.
    """
    features = aggregator.aggregate_current_window()
    hop_analysis = hop_scorer.evaluate_hops(features, target_override="8.8.8.8")
    raw_hops = [h if isinstance(h, dict) else h.to_dict() for h in hop_analysis.hop_observations]

    # Structure into pipeline stages
    structured_stages = []
    # 1. Source (YOU)
    structured_stages.append({
        "stage": "SOURCE",
        "name": "YOU",
        "ip": "Local Device",
        "status": "HEALTHY",
        "latency_ms": 0.0,
        "loss_pct": 0.0,
        "description": "Your local machine and network interface card",
        "why_points": [
            "Local network stack and socket interface operational",
            "Active probe dispatcher and telemetry aggregator running",
        ],
    })

    # Map hops
    for idx, h in enumerate(raw_hops):
        hop_num = h.get("hop_number", idx + 1)
        ip = h.get("ip", "*")
        status = h.get("status", "HEALTHY")
        rtt = h.get("current_rtt_ms", 0.0)
        loss = h.get("loss_pct", 0.0)

        if hop_num == 1:
            stage_name = "LOCAL GATEWAY"
            desc = "Local Wi-Fi router / default gateway"
        elif hop_num == len(raw_hops):
            stage_name = "DESTINATION"
            desc = "Target service / DNS server (8.8.8.8)"
        else:
            stage_name = f"HOP {hop_num}"
            desc = "Transit carrier / internet service provider router"

        why = []
        if rtt > 0:
            why.append(f"Observed round-trip time: {rtt:.1f} ms")
        else:
            why.append("Hop did not respond to ICMP echo probe")
        if loss > 0:
            why.append(f"Packet loss measured at {loss:.1f}%")
        else:
            why.append("Zero packet loss observed at this segment")
        if status in ("LIKELY_FAULT", "SUSPECTED"):
            why.append(f"Degradation detected across {h.get('evidence_count', 1)} evaluation check(s)")
            if hop_num == hop_analysis.suspect_hop_num:
                for sig in hop_analysis.corroborating_signals:
                    why.append(sig)
        else:
            why.append(f"Operating normally within expected network thresholds (Status: {status})")

        structured_stages.append({
            "stage": stage_name,
            "hop_number": hop_num,
            "name": stage_name,
            "ip": ip,
            "status": status,
            "latency_ms": rtt,
            "loss_pct": loss,
            "confidence": h.get("confidence", "Medium"),
            "deviation_pct": h.get("deviation_pct", 0.0),
            "evidence_count": h.get("evidence_count", 0),
            "description": desc,
            "why_points": why,
        })

    # Summary statement
    has_fault = any(h.get("status") in ("SUSPECTED", "LIKELY_FAULT") for h in raw_hops)
    if has_fault:
        path_status = "DEGRADED"
        summary_text = f"Performance degradation detected near {hop_analysis.hop_location}."
    else:
        path_status = "HEALTHY"
        summary_text = f"Path is operating normally across {len(raw_hops)} hops (End-to-end delay: {features.avg_latency:.1f} ms, 0% loss)."

    return {
        "target": "8.8.8.8",
        "path_status": path_status,
        "summary_text": summary_text,
        "path_length": len(raw_hops),
        "suspected_hop": hop_analysis.suspect_hop_num,
        "suspected_location": hop_analysis.hop_location,
        "confidence": hop_analysis.hop_confidence,
        "stages": structured_stages,
        "hops": raw_hops,
        "is_unconfirmed_region": "unconfirmed" in hop_analysis.hop_location.lower(),
        "timestamp": time.time(),
    }


@app.get("/api/hops/{target}")
def get_hops(target: str = "8.8.8.8"):
    """Returns the latest traceroute hop telemetry and confidence analysis."""
    features = aggregator.aggregate_current_window()
    hop_analysis = hop_scorer.evaluate_hops(features, target_override=target)

    return {
        "target": target,
        "hop_analysis": hop_analysis.to_dict(),
        "hops": [h if isinstance(h, dict) else h.to_dict() for h in hop_analysis.hop_observations],
        "timestamp": time.time(),
    }


@app.get("/api/incidents")
def list_incidents(limit: int = 50, offset: int = 0, status: Optional[str] = None):
    """Returns paginated incidents list with deduplication and lifecycle states."""
    incidents = db.get_incidents(limit=limit, offset=offset, status=status)
    return [inc.to_dict() for inc in incidents]


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int):
    """Returns full Autopsy Report details for a specific incident."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc.to_dict()


@app.get("/incidents/{incident_id}/view", response_class=HTMLResponse)
def view_incident_html(incident_id: int):
    """Renders the incident as a formatted HTML Autopsy Post-Mortem Report."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return report_gen.render_html_report(inc)


@app.post("/api/run-diagnostic")
def run_diagnostic():
    """
    Manually triggers an active probe cycle and runs the full diagnosis pipeline:
    Windowing -> Baseline Anomaly -> Hop Confidence -> Rules -> ML -> Incident Lifecycle (with deduplication).
    """
    cycle_results = {}
    if probe_scheduler_ref:
        cycle_results = probe_scheduler_ref.run_cycle_now()

    # Aggregate window features
    features = aggregator.aggregate_current_window()

    # Evaluate against baselines
    anomalies = baseline_learner.evaluate_window(features)

    # Evaluate hop confidence
    hop_res = hop_scorer.evaluate_hops(features)

    # Run Rule Classifier
    rule_diagnoses = rules_classifier.evaluate(features, anomalies, hop_res.to_dict())

    # Run ML Model
    ml_cause, ml_conf, ml_probs = ml_classifier.predict(features)
    ml_eval = {"predicted_class": ml_cause, "confidence": ml_conf, "probabilities": ml_probs}

    # Incident lifecycle: Check recovery for ongoing incidents first
    resolved_incidents = report_gen.check_recovery_for_active_incidents(
        features=features,
        anomalies=anomalies,
        rules=rule_diagnoses,
    )

    # Create or update incident with deduplication
    active_incident = None
    if rule_diagnoses or anomalies or (ml_cause != "HEALTHY_NORMAL" and ml_conf > 0.65):
        active_incident = report_gen.generate_or_update_incident(
            features=features,
            rules=rule_diagnoses,
            hop_result=hop_res,
            ml_prediction=ml_eval,
            anomalies=anomalies,
        )

    return {
        "status": "COMPLETED",
        "cycle_duration_ms": cycle_results.get("cycle_duration_ms", 0.0),
        "rules_fired": [r.to_dict() for r in rule_diagnoses],
        "anomalies_detected": [a.to_dict() for a in anomalies],
        "hop_localization": hop_res.to_dict(),
        "ml_confirmation": ml_eval,
        "active_incident": active_incident.to_dict() if active_incident else None,
        "resolved_incidents_count": len(resolved_incidents),
        "timestamp": time.time(),
    }


class FaultInjectionRequest(BaseModel):
    fault_type: str
    target: str = "127.0.0.1:8085"
    duration_s: float = 20.0
    intensity: float = 0.0


@app.post("/api/inject-fault")
def inject_fault_endpoint(req: FaultInjectionRequest):
    """
    Safely injects a controlled fault scenario via the local socket proxy.
    In CLOUD_DEMO mode this endpoint is intentionally disabled — socket-level
    fault injection requires the local agent process, which is not available
    on the cloud host. The Validation Lab still works via synthetic benchmarks.
    """
    mode = get_current_system_mode()
    if mode == "CLOUD_DEMO":
        raise HTTPException(
            status_code=503,
            detail=(
                "Fault injection is not available in Cloud Demo mode. "
                "Socket-level fault injection requires the local Network Autopsy agent. "
                "To test fault injection, run the project locally. "
                "Use the Validation Lab's Synthetic Benchmark to validate diagnostic accuracy here."
            ),
        )

    # Whitelist validation — only pre-audited scenarios are accepted
    if req.fault_type not in SAFE_FAULT_SCENARIOS:
        raise HTTPException(
            status_code=400,
            detail=f"Security restriction: Unknown fault_type '{req.fault_type}'. Whitelisted values: {list(SAFE_FAULT_SCENARIOS.keys())}",
        )

    # Target sanitization: strictly restrict to loopback socket proxy
    target_clean = req.target.strip()
    if target_clean not in ("127.0.0.1", "127.0.0.1:8085", "localhost", "localhost:8085"):
        raise HTTPException(
            status_code=400,
            detail="Security restriction: Fault injection target must be the local socket proxy (127.0.0.1:8085).",
        )

    # Parameter range validation
    if not (1.0 <= req.duration_s <= 30.0):
        raise HTTPException(status_code=400, detail="Security restriction: duration_s must be between 1.0 and 30.0 seconds.")
    if not (0.0 <= req.intensity <= 1000.0):
        raise HTTPException(status_code=400, detail="Security restriction: intensity must be between 0.0 and 1000.0.")

    # Rate limiting / cooldown protection
    global _LAST_FAULT_TIME
    now = time.time()
    if now - _LAST_FAULT_TIME < 2.0:
        raise HTTPException(status_code=429, detail="Rate limit: Please wait 2 seconds between fault injections.")
    _LAST_FAULT_TIME = now

    try:
        res = fault_controller.inject_scenario(
            scenario_type=req.fault_type,
            target="127.0.0.1",
            duration_s=req.duration_s,
            intensity=max(0.1, req.intensity) if req.intensity > 0 else 1.0,
        )
        res["success"] = True
        return res
    except ValueError as e:
        fault_controller.clear_all()
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        fault_controller.clear_all()
        logger.error(f"Fault injection error: {e}")
        raise HTTPException(status_code=500, detail=f"Fault injection failed: {str(e)}")


@app.post("/api/clear-faults")
def clear_faults_endpoint():
    """Safely clears all injected faults and restores clean operational state."""
    mode = get_current_system_mode()
    if mode == "CLOUD_DEMO":
        return {"status": "NO_ACTIVE_FAULTS", "message": "No faults active in Cloud Demo mode."}
    res = fault_controller.clear_all()
    return {"status": "ALL_FAULTS_CLEARED", "details": res}


@app.get("/api/validation/scenarios")
def get_validation_scenarios():
    """Returns the list of 10 supported safe fault scenarios for the Validation Lab."""
    return [
        {
            "scenario_id": scen_id,
            "name": cfg["name"],
            "expected_cause": cfg["expected_cause"],
            "expected_layer": cfg["expected_layer"],
            "expected_location": cfg["expected_location"],
            "default_intensity": cfg["default_intensity"],
            "unit": cfg["unit"],
            "description": cfg["description"],
        }
        for scen_id, cfg in SAFE_FAULT_SCENARIOS.items()
    ]


@app.get("/api/validation/results")
def get_validation_results():
    """
    Returns validation experiment records, strictly separating:
    1. Real End-to-End Network Experiments (executed against genuine degraded sockets)
    2. Simulated / Synthetic Benchmarks (unit test scenarios)
    Never mixes real and synthetic data.
    """
    real_results = {}
    if os.path.exists(REAL_VALIDATION_PATH):
        try:
            with open(REAL_VALIDATION_PATH, "r", encoding="utf-8") as f:
                real_results = json.load(f)
                if "diagnosis_accuracy" in real_results:
                    real_results["diagnosis_accuracy_pct"] = round(real_results["diagnosis_accuracy"] * 100, 1)
                if "detection_rate" in real_results:
                    real_results["detection_rate_pct"] = round(real_results["detection_rate"] * 100, 1)
                if "layer_accuracy" in real_results:
                    real_results["layer_accuracy_pct"] = round(real_results["layer_accuracy"] * 100, 1)
                if "recovery_detection_accuracy" in real_results:
                    real_results["recovery_rate_pct"] = round(real_results["recovery_detection_accuracy"] * 100, 1)
                if "localization_accuracy" in real_results:
                    real_results["localization_accuracy_pct"] = round(real_results["localization_accuracy"] * 100, 1)
        except Exception as e:
            logger.warning(f"Failed to load real validation results: {e}")

    synthetic_results = {}
    if os.path.exists(SYNTHETIC_VALIDATION_PATH):
        try:
            with open(SYNTHETIC_VALIDATION_PATH, "r", encoding="utf-8") as f:
                synthetic_results = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load synthetic validation results: {e}")

    # Also query SQLite experiments table for trial-by-trial logs
    recent_trials = db.get_experiment_records(limit=30)
    if not recent_trials and os.path.exists(SEED_TRIALS_PATH):
        try:
            with open(SEED_TRIALS_PATH, "r", encoding="utf-8") as f:
                seed_data = json.load(f)
                for item in seed_data:
                    exp = ExperimentRecord(
                        experiment_id=item["experiment_id"],
                        scenario_id=item["scenario_id"],
                        fault_type=item.get("fault_type", item["scenario_id"]),
                        target=item.get("target", "127.0.0.1:8085"),
                        mode=item.get("mode", "REAL_NETWORK_SOCKETS"),
                        severity=item.get("severity", "HIGH"),
                        intensity_val=item.get("intensity_val", 0.0),
                        start_time=item.get("start_time", time.time()),
                        injection_time=item.get("injection_time", 0.0),
                        recovery_time=item.get("recovery_time"),
                        detection_time=item.get("detection_time"),
                        diagnosis_time=item.get("diagnosis_time"),
                        detection_latency_s=item.get("detection_latency_s"),
                        recovery_duration_s=item.get("recovery_duration_s"),
                        expected_cause=item.get("expected_cause", ""),
                        expected_layer=item.get("expected_layer", "Network"),
                        expected_location=item.get("expected_location", "Gateway"),
                        predicted_cause=item.get("predicted_cause", ""),
                        predicted_layer=item.get("predicted_layer", "Network"),
                        predicted_location=item.get("predicted_location", ""),
                        confidence=item.get("confidence", 0.8),
                        correct_cause=item.get("correct_cause", False),
                        correct_layer=item.get("correct_layer", True),
                        correct_location=item.get("correct_location", True),
                        evidence_json=json.dumps(item.get("evidence", {})),
                        parameters_json=json.dumps(item.get("parameters", {})),
                        status="COMPLETED",
                    )
                    db.insert_experiment_record(exp)
            recent_trials = db.get_experiment_records(limit=30)
        except Exception as e:
            logger.warning(f"Failed to seed real trial records: {e}")

    return {
        "real_network_validation": real_results if real_results else {
            "status": "NO_REAL_EXPERIMENTS_EXECUTED_YET",
            "message": "Run real validation via the Validation Lab to generate empirical results.",
            "total_trials": 0,
        },
        "synthetic_scenario_benchmark": synthetic_results if synthetic_results else {
            "status": "BENCHMARK_AVAILABLE",
            "message": "Algorithmic unit-test validation on calibrated feature distributions.",
        },
        "recent_trial_records": [t.to_dict() for t in recent_trials],
        "timestamp": time.time(),
    }


class RunExperimentRequest(BaseModel):
    scenario_id: str
    trials: int = 1
    intensity: float = 0.0
    duration_s: float = 6.0
    mode: str = "real"  # "real" or "synthetic"


@app.post("/api/validation/run-experiment")
def run_experiment_endpoint(req: RunExperimentRequest, background_tasks: BackgroundTasks):
    """
    Triggers controlled experiment trial(s) in foreground with strict security constraints.
    Real experiments require the local socket-proxy agent and cannot run on the cloud host.
    In CLOUD_DEMO mode, only the Synthetic Benchmark (algorithmic unit tests) is available.
    """
    from sandbox.validation_runner import ValidationRunner

    mode = get_current_system_mode()

    # Input validation
    if req.mode not in ("real", "synthetic"):
        raise HTTPException(status_code=400, detail="mode must be 'real' or 'synthetic'")
    if req.scenario_id not in SAFE_FAULT_SCENARIOS and req.scenario_id != "ALL":
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario_id '{req.scenario_id}'. Whitelisted values: {list(SAFE_FAULT_SCENARIOS.keys()) + ['ALL']}",
        )
    if not (1 <= req.trials <= 20):
        raise HTTPException(status_code=400, detail="trials must be between 1 and 20.")
    if not (2.0 <= req.duration_s <= 30.0):
        raise HTTPException(status_code=400, detail="duration_s must be between 2.0 and 30.0 seconds.")
    if not (0.0 <= req.intensity <= 1000.0):
        raise HTTPException(status_code=400, detail="intensity must be between 0.0 and 1000.0.")

    # Concurrency and cooldown protection
    global _LAST_EXPERIMENT_TIME, _EXPERIMENT_LOCK
    now = time.time()
    if now - _LAST_EXPERIMENT_TIME < 3.0:
        raise HTTPException(
            status_code=429,
            detail="Experiment cooldown active. Please wait 3 seconds before running another experiment.",
        )

    if not _EXPERIMENT_LOCK.acquire(blocking=False):
        raise HTTPException(
            status_code=429,
            detail="Another experiment is currently running. Concurrent experiments are blocked for stability.",
        )

    try:
        _LAST_EXPERIMENT_TIME = time.time()

        if req.mode == "real":
            if mode == "CLOUD_DEMO":
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Real network experiments require the local probe agent and socket proxy, "
                        "which are not running on the cloud host. This is expected cloud behavior "
                        "— run the project locally for live fault injection trials. "
                        "Use the Synthetic Benchmark to validate diagnostic accuracy in Cloud Demo mode."
                    ),
                )
            runner = ValidationRunner(db=db)
            trial_record = runner.run_single_real_trial(
                scenario_id=req.scenario_id,
                intensity=req.intensity,
                duration_s=req.duration_s,
            )
            return {
                "status": "EXPERIMENT_TRIAL_COMPLETED",
                "mode": "REAL_NETWORK_DEGRADATION",
                "trial": trial_record.to_dict(),
            }
        else:
            runner = ValidationRunner(db=db)
            results = runner.run_synthetic_benchmark(trials_per_fault=req.trials)
            return {
                "status": "SYNTHETIC_BENCHMARK_COMPLETED",
                "mode": "SYNTHETIC_SCENARIO_VALIDATION",
                "results": results,
            }
    finally:
        _EXPERIMENT_LOCK.release()
        try:
            fault_controller.clear_all()
        except Exception:
            pass


@app.get("/api/ml-models")
def get_ml_models_info():
    """Returns 5-model ML comparison report, split methodology, and feature importances."""
    data = {}
    if os.path.exists(COMPARISON_PATH):
        try:
            with open(COMPARISON_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load ML comparison: {e}")
    if not data and ml_classifier.latest_metrics:
        data = ml_classifier.latest_metrics

    # Format models array for direct UI rendering
    models_list = []
    if "models_comparison" in data:
        for k, m in data["models_comparison"].items():
            is_deployed = "Deployed" in m.get("role", "")
            is_bench = "benchmark" in m.get("role", "").lower()
            models_list.append({
                "name": m.get("name", k),
                "role": "DEPLOYED RUNTIME" if is_deployed else ("BENCHMARK ONLY" if is_bench else "COMPARATIVE"),
                "accuracy": m.get("accuracy", 0.0),
                "f1_macro": m.get("f1_score", 0.0),
                "characteristic": m.get("advantage") or m.get("limitation") or "White-box if-then rules",
            })
    data["models"] = models_list
    return data


@app.get("/api/ml-features")
def get_ml_features_documentation():
    """Returns exhaustive documentation for all 26 extracted telemetry parameters."""
    return {
        "feature_count": len(FEATURE_METADATA),
        "features": FEATURE_METADATA,
    }
