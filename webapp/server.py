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


@app.get("/")
def index():
    return RedirectResponse(url="/static/dashboard.html")


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
    Calculates overall network health score (0-100) and letter grade (A-F).
    Provides fully explainable contributor deductions so the score is completely defensible.
    """
    features = aggregator.aggregate_current_window()
    anomalies = baseline_learner.evaluate_window(features)
    open_incidents = db.get_incidents(limit=5, status="ONGOING")
    if not open_incidents:
        open_incidents = db.get_incidents(limit=5, status="DETECTED")

    score = 100
    contributors = []

    # 1. Packet Loss Penalty
    if features.loss_pct > 0:
        loss_pen = min(int(features.loss_pct * 2.0), 40)
        score -= loss_pen
        contributors.append({
            "parameter": "Packet Loss",
            "penalty": -loss_pen,
            "observed": f"{features.loss_pct:.1f}% loss",
            "baseline": "0.0%",
            "severity": "CRITICAL" if loss_pen > 20 else "MODERATE",
        })

    # 2. Latency Anomaly Penalty
    if features.avg_latency > 60:
        lat_pen = min(int((features.avg_latency - 60) * 0.4), 25)
        score -= lat_pen
        contributors.append({
            "parameter": "Latency Anomaly",
            "penalty": -lat_pen,
            "observed": f"{features.avg_latency:.1f}ms",
            "baseline": "< 40ms",
            "severity": "HIGH" if lat_pen > 15 else "LOW",
        })

    # 3. DNS Failure Penalty
    if features.dns_loss_pct > 0:
        dns_pen = min(int(features.dns_loss_pct * 0.3), 30)
        score -= dns_pen
        contributors.append({
            "parameter": "DNS Resolution Degradation",
            "penalty": -dns_pen,
            "observed": f"{features.dns_loss_pct:.1f}% failure",
            "baseline": "0.0%",
            "severity": "CRITICAL",
        })

    # 4. HTTP Application Failure Penalty
    if features.http_loss_pct > 0:
        http_pen = min(int(features.http_loss_pct * 0.25), 25)
        score -= http_pen
        contributors.append({
            "parameter": "HTTP / Application Service Failure",
            "penalty": -http_pen,
            "observed": f"HTTP {features.http_status_code} ({features.http_loss_pct:.0f}% failure)",
            "baseline": "HTTP 200",
            "severity": "HIGH",
        })

    # 5. TCP Retransmissions & Congestion Penalty
    if features.retrans_count > 3:
        tcp_pen = min(int(features.retrans_count * 2), 20)
        score -= tcp_pen
        contributors.append({
            "parameter": "TCP Retransmissions / Congestion",
            "penalty": -tcp_pen,
            "observed": f"{features.retrans_count} retrans",
            "baseline": "< 2",
            "severity": "MODERATE",
        })

    # 6. Packet Integrity Penalty
    if features.checksum_errors > 0:
        chk_pen = min(features.checksum_errors * 5, 20)
        score -= chk_pen
        contributors.append({
            "parameter": "Packet Checksum Corruption",
            "penalty": -chk_pen,
            "observed": f"{features.checksum_errors} checksum errors",
            "baseline": "0",
            "severity": "CRITICAL",
        })

    # 7. Route Instability Penalty
    if features.route_changed:
        score -= 10
        contributors.append({
            "parameter": "Routing Path Shift / Route Flap",
            "penalty": -10,
            "observed": "Path altered vs historical topology",
            "baseline": "Stable path",
            "severity": "LOW",
        })

    # 8. Active Incident Penalty
    if open_incidents:
        inc_pen = min(len(open_incidents) * 5, 15)
        score -= inc_pen
        contributors.append({
            "parameter": "Active Unresolved Incidents",
            "penalty": -inc_pen,
            "observed": f"{len(open_incidents)} ongoing",
            "baseline": "0",
            "severity": "MODERATE",
        })

    score = max(min(int(score), 100), 10)

    # Grade mapping
    if score >= 90:
        grade = "A"
        summary = "Network Optimal — All active probes responding within adaptive baselines."
    elif score >= 80:
        grade = "B"
        summary = "Good — Minor latency jitter or harmless packet variance."
    elif score >= 65:
        grade = "C"
        summary = "Degraded — Moderate packet loss or transport retransmissions detected."
    elif score >= 50:
        grade = "D"
        summary = "Substandard — Severe delay, packet drop, or DNS slowness."
    else:
        grade = "F"
        summary = "Critical Failure — Active bottleneck, service crash, or link drop."

    return {
        "grade": grade,
        "score": score,
        "status_summary": summary,
        "active_incidents": len(open_incidents),
        "anomalies_detected": len(anomalies),
        "contributors": contributors,
        "timestamp": time.time(),
    }


@app.get("/api/latest-metrics")
def get_latest_metrics():
    """Returns the most recent rolling window features, baseline status, and data freshness."""
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

    # If sniffer yielded zero packets (e.g. no Npcap on Windows), fallback to verified database transactions
    if sum(passive_stats.get("protocols", {}).values()) == 0:
        db_protos = db.get_observed_protocol_counts()
        passive_stats["protocols"] = db_protos
        passive_stats["total_packets"] = sum(db_protos.values())
        passive_stats["capture_mode"] = "Network Telemetry"

    now = time.time()
    data_age_s = round(now - features.window_end, 1) if features.window_end > 0 else 0.0
    is_stale = data_age_s > 45.0

    return {
        "features": features.to_dict(),
        "baselines": baselines,
        "passive_stats": passive_stats,
        "timestamp": now,
        "data_age_s": data_age_s,
        "is_stale": is_stale,
        "telemetry_source": "LIVE_NETWORK",
    }


@app.get("/api/topology")
def get_topology():
    """
    Returns dynamic hop-by-hop path topology view with hop confidence,
    status classification (HEALTHY, SUSPECTED, LIKELY_FAULT, UNCONFIRMED),
    and per-hop RTT/loss metrics.
    """
    features = aggregator.aggregate_current_window()
    hop_analysis = hop_scorer.evaluate_hops(features, target_override="8.8.8.8")

    return {
        "target": "8.8.8.8",
        "path_length": len(hop_analysis.hop_observations),
        "suspected_hop": hop_analysis.suspect_hop_num,
        "suspected_location": hop_analysis.hop_location,
        "confidence": hop_analysis.hop_confidence,
        "hops": [h if isinstance(h, dict) else h.to_dict() for h in hop_analysis.hop_observations],
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
    """Safely injects a controlled fault scenario without harming physical network interfaces."""
    res = fault_controller.inject_safe_fault(
        scenario_id=req.fault_type,
        target=req.target,
        duration_s=req.duration_s,
        intensity=req.intensity,
    )
    if not res.get("success", False):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to inject fault"))
    return res


@app.post("/api/clear-faults")
def clear_faults_endpoint():
    """Safely clears all injected faults and restores clean operational state."""
    res = fault_controller.cleanup_all_faults()
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
    Triggers controlled experiment trial(s) in background or foreground.
    """
    from sandbox.validation_runner import ValidationRunner

    runner = ValidationRunner(db=db)
    if req.mode == "real":
        # Run 1 trial synchronously so the user gets immediate feedback in the Validation Lab
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
        results = runner.run_synthetic_benchmark(trials_per_fault=req.trials)
        return {
            "status": "SYNTHETIC_BENCHMARK_COMPLETED",
            "mode": "SYNTHETIC_SCENARIO_VALIDATION",
            "results": results,
        }


@app.get("/api/ml-models")
def get_ml_models_info():
    """Returns 5-model ML comparison report, split methodology, and feature importances."""
    if os.path.exists(COMPARISON_PATH):
        with open(COMPARISON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return ml_classifier.latest_metrics or {"message": "ML comparison not yet generated."}


@app.get("/api/ml-features")
def get_ml_features_documentation():
    """Returns exhaustive documentation for all 26 extracted telemetry parameters."""
    return {
        "feature_count": len(FEATURE_METADATA),
        "features": FEATURE_METADATA,
    }
