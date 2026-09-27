"""
Autopsy Report Generator for Network Autopsy.
Synthesizes:
- Rule-based expert classification
- Hop confidence & localization
- Machine learning secondary confirmation
- Evidence metrics & anomalies
Generates structured Autopsy Reports, persists to SQLite incidents table,
and renders HTML post-mortem reports.
"""
import os
import json
import time
from typing import Dict, Any, Optional, List
from jinja2 import Environment, FileSystemLoader

from storage.db import Database, get_db
from storage.models import Incident
from engine.windowing import WindowFeatures
from engine.rules import RuleDiagnosis
from engine.hop_confidence import HopLocalizationResult
from engine.baseline import MetricAnomaly


TEMPLATE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "webapp", "templates"
)


class ReportGenerator:
    def __init__(self, db: Optional[Database] = None):
        self.db = db or get_db()
        os.makedirs(TEMPLATE_DIR, exist_ok=True)
        self.jinja_env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=True
        )

    def generate_report(
        self,
        features: WindowFeatures,
        rules: List[RuleDiagnosis],
        hop_result: HopLocalizationResult,
        ml_prediction: Optional[Dict[str, Any]] = None,
        anomalies: Optional[List[MetricAnomaly]] = None,
    ) -> Incident:
        """
        Builds a comprehensive Autopsy Incident Report from engine signals.
        """
        ts = time.time()
        primary_rule = rules[0] if rules else None

        # Determine Symptom
        symptom_parts = []
        if features.loss_pct > 5.0:
            symptom_parts.append(f"packet loss of {features.loss_pct}%")
        if features.avg_latency > 60.0:
            symptom_parts.append(f"elevated latency averaging {features.avg_latency}ms (max {features.max_latency}ms)")
        if features.dns_loss_pct > 20.0 or features.dns_latency > 250.0:
            symptom_parts.append(f"DNS response degradation ({features.dns_latency}ms)")
        if features.http_loss_pct > 20.0 or features.http_status_code >= 500:
            symptom_parts.append(f"HTTP application failure (status {features.http_status_code})")
        if features.tcp_connect_loss_pct > 20.0:
            symptom_parts.append("TCP connection timeouts/refusals")
        if features.retrans_count >= 2:
            symptom_parts.append(f"{features.retrans_count} TCP retransmissions observed")
        if features.checksum_errors >= 1:
            symptom_parts.append(f"{features.checksum_errors} corrupted frame checksums")
        if features.route_changed:
            symptom_parts.append("active route hop count/sequence fluctuation")

        symptom_str = "Network anomaly detected: " + (", ".join(symptom_parts) if symptom_parts else "Intermittent performance drop")

        # Determine Layer & Cause
        if primary_rule:
            layer = primary_rule.affected_layer
            cause = primary_rule.cause_label
            rule_conf = primary_rule.confidence_score
            remediation = primary_rule.remediation_text
        else:
            layer = "Network"
            cause = "Unclassified network anomaly deviating from baseline"
            rule_conf = 0.50
            remediation = "Review recent configuration changes and monitor baseline telemetry."

        # ML Secondary Confirmation
        ml_cause = ml_prediction.get("predicted_class", "UNKNOWN") if ml_prediction else "UNKNOWN"
        ml_conf = ml_prediction.get("confidence", 0.5) if ml_prediction else 0.5

        # Combined Confidence Score (65% Expert System + 35% ML Model)
        combined_conf = round((0.65 * rule_conf) + (0.35 * ml_conf), 2)

        # Hop localization
        hop_loc = hop_result.hop_location
        hop_grade = hop_result.hop_confidence

        # Evidence dictionary
        evidence = {
            "window_duration_s": features.duration_s,
            "metrics": {
                "avg_latency_ms": features.avg_latency,
                "max_latency_ms": features.max_latency,
                "jitter_ms": features.jitter,
                "loss_pct": features.loss_pct,
                "gateway_latency_ms": features.gateway_latency,
                "gateway_loss_pct": features.gateway_loss,
                "external_latency_ms": features.external_latency,
                "external_loss_pct": features.external_loss,
                "dns_latency_ms": features.dns_latency,
                "dns_loss_pct": features.dns_loss_pct,
                "http_latency_ms": features.http_latency,
                "http_ttfb_ms": features.http_ttfb,
                "http_status_code": features.http_status_code,
                "tcp_connect_latency_ms": features.tcp_connect_latency,
                "retransmissions": features.retrans_count,
                "duplicate_acks": features.dup_ack_count,
                "checksum_errors": features.checksum_errors,
            },
            "anomalies": [a.to_dict() for a in (anomalies or [])],
            "rule_diagnoses": [r.to_dict() for r in rules],
            "hop_analysis": hop_result.to_dict(),
            "ml_evaluation": {
                "predicted_fault": ml_cause,
                "confidence": ml_conf,
            },
        }

        incident = Incident(
            timestamp=ts,
            symptom=symptom_str,
            affected_layer=layer,
            probable_cause=cause,
            confidence_score=combined_conf,
            evidence_json=json.dumps(evidence),
            hop_location=hop_loc,
            hop_confidence=hop_grade,
            remediation_text=remediation,
            status="OPEN",
        )

        incident_id = self.db.insert_incident(incident)
        incident.id = incident_id
        return incident

    def render_html_report(self, incident: Incident) -> str:
        """Renders an incident report into HTML using Jinja2."""
        template = self.jinja_env.get_template("incident_report.html")
        evidence = incident.get_evidence()
        return template.render(incident=incident, evidence=evidence)
