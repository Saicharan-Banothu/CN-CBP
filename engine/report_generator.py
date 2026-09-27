"""
Autopsy Report Generator & Incident Lifecycle Manager for Network Autopsy.
Manages:
- Incident Lifecycle State Machine: DETECTED -> CONFIRMED -> ONGOING -> RECOVERING -> RESOLVED
- Incident Deduplication: Correlates continuous symptoms into ongoing incident records
- Incident Recovery Detection: Automatically detects when network metrics return to baseline
- Full Post-Mortem Autopsy Report rendering (JSON & Jinja2 HTML).
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

    def _generate_incident_key(self, probable_cause: str, layer: str, location: str) -> str:
        """Constructs a deterministic deduplication key for correlating related symptoms."""
        cause_clean = "".join(c for c in probable_cause if c.isalnum()).lower()[:20]
        layer_clean = "".join(c for c in layer if c.isalnum()).lower()[:10]
        loc_clean = "".join(c for c in location if c.isalnum()).lower()[:15]
        return f"{cause_clean}_{layer_clean}_{loc_clean}"

    def generate_or_update_incident(
        self,
        features: WindowFeatures,
        rules: List[RuleDiagnosis],
        hop_result: HopLocalizationResult,
        ml_prediction: Optional[Dict[str, Any]] = None,
        anomalies: Optional[List[MetricAnomaly]] = None,
    ) -> Incident:
        """
        Manages incident deduplication and lifecycle state machine.
        If an open incident with matching key exists, updates occurrence count,
        appends timeline event, and refreshes evidence without spamming duplicate rows.
        """
        ts = time.time()
        primary_rule = rules[0] if rules else None

        # Build Symptom Description
        symptom_parts = []
        if features.loss_pct > 5.0:
            symptom_parts.append(f"packet loss of {features.loss_pct}%")
        if features.avg_latency > 50.0:
            symptom_parts.append(f"latency elevated to {features.avg_latency}ms (max {features.max_latency}ms)")
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
            symptom_parts.append("active route hop count/sequence mutation")

        symptom_str = "Network anomaly detected: " + (", ".join(symptom_parts) if symptom_parts else "Intermittent performance drop")

        # Determine Cause, Layer & Remediation
        if primary_rule:
            layer = primary_rule.affected_layer
            cause = primary_rule.cause_label
            rule_conf = primary_rule.confidence_score
            remediation = primary_rule.remediation_text
            alternatives = primary_rule.alternative_hypotheses
        else:
            layer = "Network"
            cause = "Unclassified network anomaly deviating from baseline"
            rule_conf = 0.50
            remediation = "Review recent network switch logs and monitor telemetry."
            alternatives = ["Transient cross-traffic burst"]

        ml_cause = ml_prediction.get("predicted_class", "UNKNOWN") if ml_prediction else "UNKNOWN"
        ml_conf = ml_prediction.get("confidence", 0.5) if ml_prediction else 0.5

        # Combined Confidence Score (65% Rules + 35% ML)
        combined_conf = round((0.65 * rule_conf) + (0.35 * ml_conf), 2)
        hop_loc = hop_result.hop_location
        hop_grade = hop_result.hop_confidence

        inc_key = self._generate_incident_key(cause, layer, hop_loc)

        # Check for existing active incident to deduplicate
        existing_incident = self.db.find_active_incident(inc_key)

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
            "alternative_hypotheses": alternatives,
        }

        if existing_incident:
            # Deduplicate & Update existing incident state
            existing_incident.occurrence_count += 1
            existing_incident.duration_s = round(ts - existing_incident.detected_at, 1)
            existing_incident.confidence_score = max(existing_incident.confidence_score, combined_conf)
            existing_incident.evidence_json = json.dumps(evidence)
            existing_incident.status = "ONGOING"

            timeline = existing_incident.get_timeline()
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            timeline.append({
                "time": ts,
                "time_str": time_str,
                "event": f"Failure condition persisting — Occurrence #{existing_incident.occurrence_count}",
                "status": "ONGOING",
            })
            existing_incident.timeline_json = json.dumps(timeline)

            self.db.update_incident(existing_incident)
            return existing_incident

        else:
            # Create a new incident
            init_status = "CONFIRMED" if combined_conf >= 0.80 else "DETECTED"
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            initial_timeline = [
                {
                    "time": ts,
                    "time_str": time_str,
                    "event": f"Symptom detected: {symptom_str}",
                    "status": "DETECTED",
                },
                {
                    "time": ts + 0.1,
                    "time_str": time_str,
                    "event": f"Root-cause diagnosis established: {cause} (Confidence: {combined_conf*100:.0f}%)",
                    "status": init_status,
                },
            ]

            incident = Incident(
                incident_key=inc_key,
                timestamp=ts,
                detected_at=ts,
                confirmed_at=ts,
                resolved_at=None,
                duration_s=0.0,
                occurrence_count=1,
                symptom=symptom_str,
                affected_layer=layer,
                probable_cause=cause,
                confidence_score=combined_conf,
                evidence_json=json.dumps(evidence),
                timeline_json=json.dumps(initial_timeline),
                hop_location=hop_loc,
                hop_confidence=hop_grade,
                remediation_text=remediation,
                status=init_status,
            )

            incident_id = self.db.insert_incident(incident)
            incident.id = incident_id
            return incident

    def check_recovery_for_active_incidents(
        self,
        features: WindowFeatures,
        anomalies: List[MetricAnomaly],
        rules: List[RuleDiagnosis],
    ) -> List[Incident]:
        """
        Checks all currently active/ongoing incidents.
        If network metrics return to baseline normal, transitions them to RESOLVED.
        """
        resolved_list = []
        active_incidents = self.db.get_incidents(limit=20, status="OPEN")
        # Also check ongoing/detected/confirmed
        for status_code in ("ONGOING", "CONFIRMED", "DETECTED", "RECOVERING"):
            active_incidents.extend(self.db.get_incidents(limit=20, status=status_code))

        # Filter unique by id
        unique_active: Dict[int, Incident] = {inc.id: inc for inc in active_incidents if inc.id}

        # Check if telemetry is currently healthy
        is_network_healthy = (
            len(rules) == 0
            and len([a for a in anomalies if a.is_anomaly]) == 0
            and features.loss_pct < 5.0
            and features.http_status_code == 200
            and features.tcp_connect_loss_pct < 20.0
        )

        now = time.time()
        time_str = time.strftime("%H:%M:%S", time.localtime(now))

        if is_network_healthy:
            for inc in unique_active.values():
                if inc.status in ("RESOLVED",):
                    continue

                inc.status = "RESOLVED"
                inc.resolved_at = now
                inc.duration_s = round(now - inc.detected_at, 1)

                timeline = inc.get_timeline()
                timeline.append({
                    "time": now,
                    "time_str": time_str,
                    "event": f"Telemetry returned to baseline normal (Loss: {features.loss_pct}%, Latency: {features.avg_latency}ms). Incident marked RESOLVED.",
                    "status": "RESOLVED",
                })
                inc.timeline_json = json.dumps(timeline)

                self.db.update_incident(inc)
                resolved_list.append(inc)

        return resolved_list

    def render_html_report(self, incident: Incident) -> str:
        """Renders an incident report into HTML using Jinja2."""
        template = self.jinja_env.get_template("incident_report.html")
        evidence = incident.get_evidence()
        timeline = incident.get_timeline()
        return template.render(incident=incident, evidence=evidence, timeline=timeline)
