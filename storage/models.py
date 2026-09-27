"""
Data models for Network Autopsy storage, diagnosis, and experiment representation.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
import time
import json


@dataclass
class EvidenceItem:
    signal: str
    observed_value: Any
    baseline_value: Any
    deviation_pct: float
    direction: str                     # "HIGH", "LOW", "NORMAL"
    source: str                        # "active_probe", "passive_capture", "traceroute", "dns_probe"
    confidence_contribution: float     # 0.0 to 1.0
    status: str                        # "ANOMALOUS", "NORMAL", "SUSPICIOUS"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class HopObservation:
    hop_number: int
    ip: str
    hostname: str = ""
    current_rtt_ms: float = 0.0
    baseline_rtt_ms: float = 0.0
    loss_pct: float = 0.0
    deviation_pct: float = 0.0
    evidence_count: int = 0
    confidence: str = "Low"            # "Low", "Medium", "High"
    status: str = "HEALTHY"            # "HEALTHY", "SUSPECTED", "LIKELY_FAULT", "UNCONFIRMED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeResult:
    id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    probe_type: str = ""               # "ping", "traceroute", "tcp_connect", "dns", "http"
    target: str = ""                   # IP, hostname, or URL
    latency_ms: float = 0.0            # average latency or rtt
    jitter_ms: float = 0.0             # latency jitter (stddev)
    loss_pct: float = 0.0              # packet loss percentage (0 - 100)
    extra_json: str = "{}"

    def get_extra(self) -> Dict[str, Any]:
        try:
            return json.loads(self.extra_json) if self.extra_json else {}
        except Exception:
            return {}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["extra"] = self.get_extra()
        return d


@dataclass
class HopData:
    id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    traceroute_run_id: str = ""
    hop_number: int = 1
    ip: str = "*"
    rtt_ms: float = 0.0
    loss_pct: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PacketEvent:
    id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    event_type: str = ""               # "retransmission", "dup_ack", "rst", "fin", "checksum_error", "stats"
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""                 # "TCP", "UDP", "ICMP", "ARP", "OTHER"
    detail_json: str = "{}"

    def get_detail(self) -> Dict[str, Any]:
        try:
            return json.loads(self.detail_json) if self.detail_json else {}
        except Exception:
            return {}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["detail"] = self.get_detail()
        return d


@dataclass
class Baseline:
    metric_name: str
    target: str
    mean: float
    stddev: float
    median: float = 0.0
    p95: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    sample_count: int = 0
    confidence_score: float = 0.0      # 0.0 to 1.0 (based on warm-up maturity)
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FaultLabel:
    id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    injected_fault_type: str = ""
    params_json: str = "{}"

    def get_params(self) -> Dict[str, Any]:
        try:
            return json.loads(self.params_json) if self.params_json else {}
        except Exception:
            return {}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["params"] = self.get_params()
        return d


@dataclass
class Incident:
    id: Optional[int] = None
    incident_key: str = ""             # Deduplication key (e.g. "gateway_congestion:192.168.1.1")
    timestamp: float = field(default_factory=time.time)
    detected_at: float = field(default_factory=time.time)
    confirmed_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None
    duration_s: float = 0.0
    occurrence_count: int = 1
    symptom: str = ""
    affected_layer: str = ""           # Physical, Data-Link, Network, Transport, Application
    probable_cause: str = ""
    confidence_score: float = 0.0      # Combined score (0.0 to 1.0)
    evidence_json: str = "{}"
    timeline_json: str = "[]"          # List of event timeline entries
    hop_location: str = "Unknown"
    hop_confidence: str = "Low"        # "Low", "Medium", "High"
    remediation_text: str = ""
    status: str = "DETECTED"           # "DETECTED", "CONFIRMED", "ONGOING", "RECOVERING", "RESOLVED"

    def get_evidence(self) -> Dict[str, Any]:
        try:
            return json.loads(self.evidence_json) if self.evidence_json else {}
        except Exception:
            return {}

    def get_timeline(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.timeline_json) if self.timeline_json else []
        except Exception:
            return []

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["evidence"] = self.get_evidence()
        d["timeline"] = self.get_timeline()
        return d


@dataclass
class ExperimentRecord:
    id: Optional[int] = None
    experiment_id: str = ""
    scenario_id: str = ""
    fault_type: str = ""
    target: str = ""
    mode: str = "REAL"                 # "REAL" or "SIMULATED"
    severity: str = "MEDIUM"           # "LOW", "MEDIUM", "HIGH"
    intensity_val: float = 0.0
    start_time: float = field(default_factory=time.time)
    injection_time: float = 0.0
    recovery_time: Optional[float] = None
    detection_time: Optional[float] = None
    diagnosis_time: Optional[float] = None
    detection_latency_s: Optional[float] = None
    recovery_duration_s: Optional[float] = None
    expected_cause: str = ""
    expected_layer: str = ""
    expected_location: str = ""
    predicted_cause: str = ""
    predicted_layer: str = ""
    predicted_location: str = ""
    confidence: float = 0.0
    correct_cause: bool = False
    correct_layer: bool = False
    correct_location: bool = False
    evidence_json: str = "{}"
    parameters_json: str = "{}"
    status: str = "INITIALIZED"        # "INITIALIZED", "RUNNING", "COMPLETED", "FAILED", "CLEANED_UP"

    def get_evidence(self) -> Dict[str, Any]:
        try:
            return json.loads(self.evidence_json) if self.evidence_json else {}
        except Exception:
            return {}

    def get_parameters(self) -> Dict[str, Any]:
        try:
            return json.loads(self.parameters_json) if self.parameters_json else {}
        except Exception:
            return {}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["evidence"] = self.get_evidence()
        d["parameters"] = self.get_parameters()
        return d
