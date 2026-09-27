"""
Data models for Network Autopsy storage and diagnosis representation.
"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
import time
import json


@dataclass
class ProbeResult:
    id: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    probe_type: str = ""       # "ping", "traceroute", "tcp_connect", "dns", "http"
    target: str = ""           # IP or hostname or URL
    latency_ms: float = 0.0    # avg latency or rtt
    jitter_ms: float = 0.0     # jitter (stddev of latency)
    loss_pct: float = 0.0      # packet loss percentage (0 - 100)
    extra_json: str = "{}"     # json string with extra fields (min/max latency, ttfb, status_code, etc.)

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
    event_type: str = ""       # "retransmission", "dup_ack", "rst", "fin", "checksum_error", "stats"
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = ""         # "TCP", "UDP", "ICMP", "ARP", "OTHER"
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
    timestamp: float = field(default_factory=time.time)
    symptom: str = ""
    affected_layer: str = ""       # Physical, Data-Link, Network, Transport, Application
    probable_cause: str = ""
    confidence_score: float = 0.0  # 0.0 to 1.0 (combined score)
    evidence_json: str = "{}"
    hop_location: str = "Unknown"
    hop_confidence: str = "Low"    # Low, Medium, High
    remediation_text: str = ""
    status: str = "OPEN"           # OPEN, RESOLVED, SUPPRESSED

    def get_evidence(self) -> Dict[str, Any]:
        try:
            return json.loads(self.evidence_json) if self.evidence_json else {}
        except Exception:
            return {}

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["evidence"] = self.get_evidence()
        return d
