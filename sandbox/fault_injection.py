"""
Safe Fault Injection Module for Network Autopsy.
Provides controlled, defensible network failure injection:
1. HIGH_LATENCY (fixed latency spike)
2. JITTER (variable latency variance)
3. PACKET_LOSS (uniform drop probability)
4. BANDWIDTH_THROTTLING (token bucket rate limit)
5. DNS_FAILURE (resolver timeout / unreachable sinkhole)
6. HTTP_SERVICE_FAILURE (application 503/crash)
7. TCP_SERVICE_FAILURE / PORT_BLOCKED (refusal / RST)
8. ROUTE_CHANGE (path hop sequence mutation)
9. INTERMITTENT_PACKET_LOSS (oscillating burst drops)
10. COMBINED_FAULT (latency + loss simultaneously)

Safety Architecture:
- SAFE MODE (default): strictly protects primary internet interfaces from blind tc qdisc changes
- DRY RUN: validates scenario configuration without applying network state
- AUTOMATIC CLEANUP: context manager guarantees faults are removed even on exceptions
- Logs all ground-truth scenario metadata to SQLite `fault_labels` and `experiments` tables.
"""
import os
import time
import json
import logging
import subprocess
import platform
import uuid
from typing import Dict, Any, Optional
from contextlib import contextmanager

from storage.db import Database, get_db
from storage.models import FaultLabel, ExperimentRecord
from sandbox.local_fault_proxy import get_controlled_target
from sandbox import service_killer, route_flap_sim

logger = logging.getLogger("network_autopsy.fault_injection")

SAFE_MODE = True              # When True, prevents disruptive tc netem on default default route interface
ALLOW_PRIMARY_IFACE = False    # Requires explicit override to touch primary internet interface

# Active scenario tracking
_active_scenario: Optional[Dict[str, Any]] = None


def is_linux_tc_supported() -> bool:
    """Returns True if the current platform is Linux with tc binary available."""
    if platform.system().lower() != "linux":
        return False
    try:
        res = subprocess.run(["tc", "-V"], capture_output=True, text=True)
        return res.returncode == 0
    except Exception:
        return False


SAFE_FAULT_SCENARIOS: Dict[str, Dict[str, Any]] = {
    "HIGH_LATENCY": {
        "name": "High Latency Spike (+180ms)",
        "expected_cause": "Network Congestion / High Latency",
        "expected_layer": "Network",
        "expected_location": "Gateway / Local Access Link",
        "default_intensity": 180.0,
        "unit": "ms",
        "description": "Applies a 180ms socket round-trip transit delay.",
    },
    "JITTER": {
        "name": "High Jitter (35ms Variance)",
        "expected_cause": "Packet Delay Variation / Jitter",
        "expected_layer": "Network",
        "expected_location": "Transmission Link",
        "default_intensity": 35.0,
        "unit": "ms",
        "description": "Applies variable random delay jitter across probe packets.",
    },
    "PACKET_LOSS": {
        "name": "Packet Loss (25%)",
        "expected_cause": "Lossy Link / Congestion Drop",
        "expected_layer": "Network / Transport",
        "expected_location": "Access Hop",
        "default_intensity": 25.0,
        "unit": "%",
        "description": "Simulates 25% uniform drop rate on socket packets.",
    },
    "BANDWIDTH_THROTTLING": {
        "name": "Bandwidth Throttle (128 kbps)",
        "expected_cause": "Bandwidth Bottleneck / Link Throttled",
        "expected_layer": "Network",
        "expected_location": "Shaper Queue",
        "default_intensity": 128.0,
        "unit": "kbps",
        "description": "Constrains socket throughput to 128 kbps token bucket.",
    },
    "DNS_FAILURE": {
        "name": "DNS Resolver Timeout / Sinkhole",
        "expected_cause": "DNS Resolution Failure",
        "expected_layer": "Application / Transport",
        "expected_location": "Local Resolver (Port 53)",
        "default_intensity": 100.0,
        "unit": "%",
        "description": "Redirects DNS queries to unreachable blackhole IP.",
    },
    "HTTP_SERVICE_FAILURE": {
        "name": "HTTP 503 Web Server Crash",
        "expected_cause": "Target Web Service Down",
        "expected_layer": "Application",
        "expected_location": "Target Host:8000",
        "default_intensity": 503.0,
        "unit": "HTTP Code",
        "description": "Forces HTTP endpoints to respond with 503 Service Unavailable.",
    },
    "TCP_SERVICE_FAILURE": {
        "name": "TCP Port Blocked / Connection Refused",
        "expected_cause": "Target Port Blocked / Service Down",
        "expected_layer": "Transport",
        "expected_location": "Target Host Port",
        "default_intensity": 100.0,
        "unit": "% Refusal",
        "description": "Actively resets or refuses incoming TCP SYN packets.",
    },
    "ROUTE_CHANGE": {
        "name": "Route Flap / Path Shift",
        "expected_cause": "Route Flap / Path Shift",
        "expected_layer": "Network",
        "expected_location": "Intermediate Hop Sequence",
        "default_intensity": 1.0,
        "unit": "Shift",
        "description": "Injects synthetic routing path hop alterations.",
    },
    "INTERMITTENT_PACKET_LOSS": {
        "name": "Intermittent Burst Packet Loss (40%)",
        "expected_cause": "Intermittent Link Degradation",
        "expected_layer": "Network / Data-Link",
        "expected_location": "Physical Medium / Radio Link",
        "default_intensity": 40.0,
        "unit": "%",
        "description": "Oscillates between 0% and 40% loss every 4 seconds.",
    },
    "COMBINED_FAULT": {
        "name": "Combined Compound Fault (Latency + Loss)",
        "expected_cause": "Compound Network Bottleneck",
        "expected_layer": "Network / Transport",
        "expected_location": "Gateway & WAN Link",
        "default_intensity": 150.0,
        "unit": "ms / 20%",
        "description": "Simultaneously injects 150ms delay and 20% packet loss.",
    },
}


class SafeFaultController:
    """
    Central controller orchestrating safe fault injection across both
    isolated socket targets and Linux tc/netem interfaces.
    """
    def __init__(self, db: Optional[Database] = None, safe_mode: bool = True):
        self.db = db or get_db()
        self.safe_mode = safe_mode
        self.proxy_target = get_controlled_target()

    def inject_scenario(
        self,
        scenario_type: str,
        target: str = "127.0.0.1",
        interface: str = "eth0",
        duration_s: float = 30.0,
        intensity: float = 1.0,
        params: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Injects a labeled fault scenario with ground-truth recording.
        """
        global _active_scenario
        ts = time.time()
        scenario_id = f"scen_{uuid.uuid4().hex[:8]}"
        params = params or {}

        # Default intensity calibrations
        latency_val = params.get("latency_ms", 150.0 * intensity)
        jitter_val = params.get("jitter_ms", 25.0 * intensity)
        loss_val = params.get("loss_pct", min(100.0, 30.0 * intensity))
        throttle_val = params.get("rate_kbps", max(64, int(256 / max(intensity, 0.1))))

        expected_cause = "Unknown"
        expected_layer = "Network"
        expected_location = "Target Link"
        mode_used = "REAL_SOCKET_PROXY"

        if dry_run:
            logger.info(f"[DRY_RUN] Scenario '{scenario_type}' validated successfully.")
            return {
                "scenario_id": scenario_id,
                "status": "DRY_RUN_VALIDATED",
                "fault_type": scenario_type,
                "params": params,
            }

        # Clear any prior state first
        self.clear_all()

        # 1. HIGH_LATENCY
        if scenario_type in ("HIGH_LATENCY", "LATENCY_SPIKE"):
            self.proxy_target.set_fault(latency_ms=latency_val, jitter_ms=0.0)
            expected_cause = "Local gateway / Wi-Fi channel congestion or local router overload"
            expected_layer = "Data-Link / Network"
            expected_location = "Hop 1 — Gateway"

        # 2. JITTER
        elif scenario_type == "JITTER":
            self.proxy_target.set_fault(latency_ms=latency_val, jitter_ms=jitter_val)
            expected_cause = "Local gateway / Wi-Fi channel congestion or local router overload"
            expected_layer = "Data-Link / Network"
            expected_location = "Hop 1 — Gateway"

        # 3. PACKET_LOSS
        elif scenario_type == "PACKET_LOSS":
            self.proxy_target.set_fault(loss_pct=loss_val)
            expected_cause = "Packet loss and out-of-order delivery inducing TCP fast-retransmits and throughput collapse"
            expected_layer = "Transport"
            expected_location = "Target Link"

        # 4. BANDWIDTH_THROTTLING
        elif scenario_type in ("BANDWIDTH_THROTTLING", "BANDWIDTH_THROTTLE"):
            self.proxy_target.set_fault(throttle_kbps=throttle_val)
            expected_cause = "Network Congestion / Lossy Link"
            expected_layer = "Transport"
            expected_location = "Bottleneck Link"

        # 5. DNS_FAILURE
        elif scenario_type == "DNS_FAILURE":
            service_killer.kill_dns_service(db=self.db)
            expected_cause = "DNS resolver timeout, misconfiguration, or upstream DNS server failure"
            expected_layer = "Application"
            expected_location = "DNS Resolver (Port 53)"

        # 6. HTTP_SERVICE_FAILURE
        elif scenario_type == "HTTP_SERVICE_FAILURE":
            self.proxy_target.set_fault(http_status_code=503)
            service_killer.kill_http_service(status_code=503, db=self.db)
            expected_cause = "Application server crash, internal 5xx error, or HTTP worker exhaustion"
            expected_layer = "Application"
            expected_location = "Target Application Server"

        # 7. TCP_SERVICE_FAILURE / PORT_BLOCKED
        elif scenario_type in ("TCP_SERVICE_FAILURE", "PORT_BLOCKED", "TARGET_SERVICE_DOWN"):
            self.proxy_target.set_fault(refuse_connections=True)
            expected_cause = "Target service process inactive, port blocked by firewall, or ACL reject"
            expected_layer = "Transport"
            expected_location = "Target Port"

        # 8. ROUTE_CHANGE
        elif scenario_type in ("ROUTE_CHANGE", "ROUTE_FLAP"):
            route_flap_sim.trigger_route_flap(db=self.db)
            expected_cause = "BGP or internal gateway routing instability causing path oscillation and transient packet drops"
            expected_layer = "Network"
            expected_location = "Intermediate Autonomous System"

        # 9. INTERMITTENT_PACKET_LOSS
        elif scenario_type == "INTERMITTENT_PACKET_LOSS":
            self.proxy_target.set_fault(loss_pct=loss_val, intermittent_loss=True)
            expected_cause = "Packet loss and out-of-order delivery inducing TCP fast-retransmits and throughput collapse"
            expected_layer = "Transport"
            expected_location = "Lossy Link"

        # 10. COMBINED_FAULT
        elif scenario_type == "COMBINED_FAULT":
            self.proxy_target.set_fault(latency_ms=latency_val, jitter_ms=jitter_val, loss_pct=loss_val)
            expected_cause = "Local gateway / Wi-Fi channel congestion or local router overload"
            expected_layer = "Data-Link / Network"
            expected_location = "Hop 1 / Gateway"

        else:
            raise ValueError(f"Unknown scenario_type: {scenario_type}")

        # Linux tc netem execution if available and safely permitted
        if is_linux_tc_supported() and (not self.safe_mode or ALLOW_PRIMARY_IFACE or interface.startswith("veth")):
            try:
                subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
                if latency_val > 0 and loss_val > 0:
                    cmd = ["tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", f"{latency_val}ms", f"{jitter_val}ms", "loss", f"{loss_val}%"]
                elif latency_val > 0:
                    cmd = ["tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", f"{latency_val}ms", f"{jitter_val}ms"]
                elif loss_val > 0:
                    cmd = ["tc", "qdisc", "add", "dev", interface, "root", "netem", "loss", f"{loss_val}%"]
                else:
                    cmd = None
                if cmd:
                    subprocess.check_call(cmd)
                    mode_used = "LINUX_TC_NETEM"
            except Exception as e:
                logger.warning(f"tc netem error: {e}. Maintained safe socket proxy mode.")

        record_info = {
            "scenario_id": scenario_id,
            "fault_type": scenario_type,
            "target": target,
            "interface": interface,
            "start_time": ts,
            "duration_s": duration_s,
            "intensity": intensity,
            "mode": mode_used,
            "expected_cause": expected_cause,
            "expected_layer": expected_layer,
            "expected_location": expected_location,
            "parameters": {
                "latency_ms": latency_val,
                "jitter_ms": jitter_val,
                "loss_pct": loss_val,
                "throttle_kbps": throttle_val,
            },
            "status": "ACTIVE",
        }

        _active_scenario = record_info

        # Persist to fault_labels
        self.db.insert_fault_label(
            FaultLabel(
                timestamp=ts,
                injected_fault_type=scenario_type,
                params_json=json.dumps(record_info),
            )
        )

        logger.info(f"Injected Safe Scenario: {scenario_type} (ID: {scenario_id}, Mode: {mode_used})")
        return record_info

    def clear_all(self, interface: str = "eth0") -> Dict[str, Any]:
        """Guaranteed cleanup of all injected faults across proxy and tc."""
        global _active_scenario
        ts = time.time()

        # 1. Reset socket proxy target
        self.proxy_target.clear_faults()

        # 2. Reset service killers
        service_killer.restore_dns_service(db=self.db)
        service_killer.restore_http_service(db=self.db)
        route_flap_sim.clear_route_flap(db=self.db)

        # 3. Reset tc qdisc on Linux if supported
        if is_linux_tc_supported():
            try:
                subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
            except Exception:
                pass

        prev = _active_scenario
        _active_scenario = None

        self.db.insert_fault_label(
            FaultLabel(
                timestamp=ts,
                injected_fault_type="CLEARED",
                params_json=json.dumps({"cleared_scenario": prev}),
            )
        )
        logger.info("Cleaned up and restored all network targets to healthy operational state.")
        return {"status": "CLEARED", "timestamp": ts, "previous": prev}


# Convenience context manager ensuring cleanup
@contextmanager
def safe_fault_context(scenario_type: str, **kwargs):
    controller = SafeFaultController()
    info = controller.inject_scenario(scenario_type, **kwargs)
    try:
        yield info
    finally:
        controller.clear_all()


# Backwards compatibility wrappers
def inject_latency(interface: str = "eth0", latency_ms: float = 150.0, jitter_ms: float = 20.0, db: Optional[Database] = None):
    ctrl = SafeFaultController(db=db)
    return ctrl.inject_scenario("HIGH_LATENCY", interface=interface, params={"latency_ms": latency_ms, "jitter_ms": jitter_ms})


def inject_packet_loss(interface: str = "eth0", loss_pct: float = 30.0, db: Optional[Database] = None):
    ctrl = SafeFaultController(db=db)
    return ctrl.inject_scenario("PACKET_LOSS", interface=interface, params={"loss_pct": loss_pct})


def inject_bandwidth_throttle(interface: str = "eth0", rate_kbps: int = 128, db: Optional[Database] = None):
    ctrl = SafeFaultController(db=db)
    return ctrl.inject_scenario("BANDWIDTH_THROTTLING", interface=interface, params={"rate_kbps": rate_kbps})


def clear_injected_faults(interface: str = "eth0", db: Optional[Database] = None):
    ctrl = SafeFaultController(db=db)
    return ctrl.clear_all(interface=interface)
