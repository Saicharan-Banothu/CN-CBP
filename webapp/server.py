"""
FastAPI Server for Network Autopsy.
Exposes REST APIs for telemetry, health grades, hop localization, incident reports,
manual diagnostic execution, and sandbox fault injection.
Serves static dashboard and rendered HTML autopsy reports.
"""
import os
import time
import json
import logging
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from storage.db import Database, get_db
from storage.models import Incident
from engine.windowing import WindowAggregator, WindowFeatures
from engine.baseline import AdaptiveBaselineLearner
from engine.rules import RuleClassifier
from engine.hop_confidence import HopConfidenceScorer
from engine.ml_classifier import get_ml_classifier, COMPARISON_PATH, RULES_PATH
from engine.report_generator import ReportGenerator
from agent.probe_scheduler import ProbeScheduler
from agent.passive_capture import PassiveCaptureAgent
from sandbox import fault_injection, service_killer, route_flap_sim

logger = logging.getLogger("network_autopsy.server")

# Base Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "webapp", "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "webapp", "templates")

app = FastAPI(
    title="Network Autopsy",
    description="Multi-Parameter Network Failure Diagnosis and Root-Cause Localization Tool",
    version="1.0.0",
)

# Shared instances (initialized at startup or main)
db = get_db()
aggregator = WindowAggregator(db)
baseline_learner = AdaptiveBaselineLearner(db)
rules_classifier = RuleClassifier()
hop_scorer = HopConfidenceScorer(db)
ml_classifier = get_ml_classifier()
report_gen = ReportGenerator(db)

# References to background agents (set by main.py)
probe_scheduler_ref: Optional[ProbeScheduler] = None
passive_capture_ref: Optional[PassiveCaptureAgent] = None

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index():
    return RedirectResponse(url="/static/dashboard.html")


@app.get("/api/demo-service/health")
def demo_service_health():
    """
    Demo HTTP endpoint used by active HTTP probe.
    Can be toggled by the sandbox service killer to simulate HTTP application failure.
    """
    if not service_killer.SERVICE_STATES["http_healthy"]:
        code = service_killer.SERVICE_STATES["http_error_code"]
        raise HTTPException(status_code=code, detail="Simulated HTTP Service Down")
    return {
        "status": "UP",
        "service": "NetworkAutopsyDemoLocalEndpoint",
        "timestamp": time.time(),
    }


@app.get("/api/health")
def get_health():
    """Calculates overall network health score (A-F grade) from recent metrics vs baseline."""
    features = aggregator.aggregate_current_window()
    anomalies = baseline_learner.evaluate_window(features)
    open_incidents = db.get_incidents(limit=5, status="OPEN")

    score = 100

    # Penalties based on metrics
    if features.loss_pct > 0:
        score -= min(features.loss_pct * 2.0, 45)
    if features.avg_latency > 60:
        score -= min((features.avg_latency - 60) * 0.4, 25)
    if features.dns_loss_pct > 0:
        score -= 25
    if features.http_loss_pct > 0:
        score -= 20
    if features.retrans_count > 3:
        score -= min(features.retrans_count * 2, 15)
    if features.checksum_errors > 0:
        score -= 20
    if features.route_changed:
        score -= 10
    if open_incidents:
        score -= len(open_incidents) * 5

    score = max(min(int(score), 100), 10)

    # Grade mapping
    if score >= 90:
        grade = "A"
        summary = "Network Optimal — All probes responding within baseline."
    elif score >= 80:
        grade = "B"
        summary = "Good — Minor latency or packet jitter variance."
    elif score >= 65:
        grade = "C"
        summary = "Degraded — Moderate packet loss or retransmissions detected."
    elif score >= 50:
        grade = "D"
        summary = "Substandard — Severe delay, packet drop, or DNS slowness."
    else:
        grade = "F"
        summary = "Critical Failure — Active bottleneck, service crash, or link down."

    return {
        "grade": grade,
        "score": score,
        "status_summary": summary,
        "active_incidents": len(open_incidents),
        "anomalies_detected": len(anomalies),
        "timestamp": time.time(),
    }


@app.get("/api/latest-metrics")
def get_latest_metrics():
    """Returns the most recent rolling window's features and passive packet stats."""
    features = aggregator.aggregate_current_window()
    passive_stats = passive_capture_ref.get_stats() if passive_capture_ref else {
        "sniffer_active": False,
        "protocols": {"TCP": 45, "UDP": 12, "ICMP": 6, "ARP": 2, "OTHER": 0},
        "events": {},
    }
    return {
        "features": features.to_dict(),
        "passive_stats": passive_stats,
        "timestamp": time.time(),
    }


@app.get("/api/hops/{target}")
def get_hops(target: str = "8.8.8.8"):
    """Returns the latest traceroute hop telemetry and confidence analysis."""
    recent_runs = db.get_latest_traceroute_runs(num_runs=3)
    hops_list = []
    if recent_runs:
        _, _, latest_hops = recent_runs[0]
        hops_list = [h.to_dict() for h in latest_hops]

    features = aggregator.aggregate_current_window()
    hop_analysis = hop_scorer.evaluate_hops(features, target_override=target)

    return {
        "target": target,
        "hops": hops_list,
        "hop_analysis": hop_analysis.to_dict(),
        "timestamp": time.time(),
    }


@app.get("/api/incidents")
def list_incidents(limit: int = 50, offset: int = 0, status: Optional[str] = None):
    """Returns paginated incidents list."""
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
    """Manually triggers an active probe cycle and runs the full diagnosis pipeline."""
    # Run active probe cycle
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

    # Generate incident report if anomaly / rules fired
    created_incident = None
    if rule_diagnoses or anomalies or (ml_cause != "HEALTHY_NORMAL" and ml_conf > 0.65):
        created_incident = report_gen.generate_report(
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
        "incidents_generated": [created_incident.to_dict()] if created_incident else [],
    }


class FaultInjectionRequest(BaseModel):
    fault_type: str
    interface: str = "eth0"
    params: Dict[str, Any] = {}


@app.post("/api/inject-fault")
def inject_fault_endpoint(req: FaultInjectionRequest):
    """Demo-mode endpoint to inject a fault from the dashboard."""
    f = req.fault_type
    result = {}

    if f == "LOCAL_GATEWAY_CONGESTION" or f == "LATENCY_JITTER":
        result = fault_injection.inject_latency(
            interface=req.interface, latency_ms=180.0, jitter_ms=35.0, db=db
        )
    elif f == "PACKET_LOSS":
        result = fault_injection.inject_packet_loss(
            interface=req.interface, loss_pct=30.0, db=db
        )
    elif f == "BANDWIDTH_THROTTLE":
        result = fault_injection.inject_bandwidth_throttle(
            interface=req.interface, rate_kbps=128, db=db
        )
    elif f == "DNS_FAILURE":
        result = service_killer.kill_dns_service(db=db)
    elif f == "HTTP_SERVICE_DOWN":
        result = service_killer.kill_http_service(status_code=503, db=db)
    elif f == "ROUTE_FLAP":
        result = route_flap_sim.trigger_route_flap(db=db)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown fault type: {f}")

    return {"status": "FAULT_INJECTED", "fault": result}


@app.post("/api/clear-faults")
def clear_faults_endpoint():
    """Clears all injected faults."""
    res1 = fault_injection.clear_injected_faults(db=db)
    res2 = service_killer.restore_dns_service(db=db)
    res3 = service_killer.restore_http_service(db=db)
    res4 = route_flap_sim.clear_route_flap(db=db)
    return {
        "status": "ALL_FAULTS_CLEARED",
        "details": [res1, res2, res3, res4],
    }


@app.get("/api/ml-models")
def get_ml_models_info():
    """Returns Decision Tree vs Random Forest validation comparison report."""
    if os.path.exists(COMPARISON_PATH):
        with open(COMPARISON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"message": "ML comparison report not yet generated."}
