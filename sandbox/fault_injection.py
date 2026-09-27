"""
Fault Injection Module for Network Autopsy.
Wraps Linux `tc`/`netem` commands to inject:
- Latency (ms)
- Jitter (ms)
- Packet loss (%)
- Bandwidth throttling (kbps)
Also provides a simulation mode for cross-platform testing (Windows/macOS)
and demo presentations.
Logs every injected fault to SQLite `fault_labels` table.
"""
import os
import time
import json
import logging
import subprocess
import platform
from typing import Dict, Any, Optional

from storage.db import Database, get_db
from storage.models import FaultLabel

logger = logging.getLogger("network_autopsy.fault_injection")

# Global in-memory simulated fault state (used when Linux tc is not available or for demo simulation)
_simulated_fault: Optional[Dict[str, Any]] = None


def is_linux_tc_supported() -> bool:
    """Returns True if the current platform is Linux with tc available."""
    if platform.system().lower() != "linux":
        return False
    try:
        res = subprocess.run(["tc", "-V"], capture_output=True, text=True)
        return res.returncode == 0
    except Exception:
        return False


def get_current_fault() -> Optional[Dict[str, Any]]:
    global _simulated_fault
    return _simulated_fault


def inject_latency(
    interface: str = "eth0",
    latency_ms: float = 150.0,
    jitter_ms: float = 20.0,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """Injects latency and jitter using netem or simulation mode."""
    global _simulated_fault
    db = db or get_db()
    ts = time.time()
    params = {"interface": interface, "latency_ms": latency_ms, "jitter_ms": jitter_ms}

    if is_linux_tc_supported():
        try:
            # Clear existing root qdisc
            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
            cmd = ["tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", f"{latency_ms}ms", f"{jitter_ms}ms"]
            subprocess.check_call(cmd)
            status = "APPLIED_TC_NETEM"
        except Exception as e:
            logger.error(f"tc command failed: {e}. Using simulated mode.")
            status = f"SIMULATED (tc error: {e})"
    else:
        status = "SIMULATED_DEMO_MODE"

    _simulated_fault = {
        "fault_type": "LATENCY_JITTER",
        "params": params,
        "timestamp": ts,
        "status": status,
    }

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="LATENCY_JITTER",
            params_json=json.dumps(params),
        )
    )
    logger.info(f"Injected latency fault: {params} (Status: {status})")
    return _simulated_fault


def inject_packet_loss(
    interface: str = "eth0",
    loss_pct: float = 30.0,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """Injects packet loss percentage using netem or simulation mode."""
    global _simulated_fault
    db = db or get_db()
    ts = time.time()
    params = {"interface": interface, "loss_pct": loss_pct}

    if is_linux_tc_supported():
        try:
            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
            cmd = ["tc", "qdisc", "add", "dev", interface, "root", "netem", "loss", f"{loss_pct}%"]
            subprocess.check_call(cmd)
            status = "APPLIED_TC_NETEM"
        except Exception as e:
            logger.error(f"tc command failed: {e}. Using simulated mode.")
            status = f"SIMULATED (tc error: {e})"
    else:
        status = "SIMULATED_DEMO_MODE"

    _simulated_fault = {
        "fault_type": "PACKET_LOSS",
        "params": params,
        "timestamp": ts,
        "status": status,
    }

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="PACKET_LOSS",
            params_json=json.dumps(params),
        )
    )
    logger.info(f"Injected packet loss fault: {params} (Status: {status})")
    return _simulated_fault


def inject_bandwidth_throttle(
    interface: str = "eth0",
    rate_kbps: int = 128,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """Throttles bandwidth to induce queuing delay / congestion."""
    global _simulated_fault
    db = db or get_db()
    ts = time.time()
    params = {"interface": interface, "rate_kbps": rate_kbps}

    if is_linux_tc_supported():
        try:
            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
            cmd = [
                "tc", "qdisc", "add", "dev", interface, "root", "tbf",
                "rate", f"{rate_kbps}kbit", "burst", "32kbit", "latency", "400ms"
            ]
            subprocess.check_call(cmd)
            status = "APPLIED_TC_TBF"
        except Exception as e:
            logger.error(f"tc command failed: {e}. Using simulated mode.")
            status = f"SIMULATED (tc error: {e})"
    else:
        status = "SIMULATED_DEMO_MODE"

    _simulated_fault = {
        "fault_type": "BANDWIDTH_THROTTLE",
        "params": params,
        "timestamp": ts,
        "status": status,
    }

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="BANDWIDTH_THROTTLE",
            params_json=json.dumps(params),
        )
    )
    logger.info(f"Injected bandwidth throttle: {params} (Status: {status})")
    return _simulated_fault


def clear_injected_faults(interface: str = "eth0", db: Optional[Database] = None) -> Dict[str, Any]:
    """Clears all active tc qdisc rules and resets simulated fault state."""
    global _simulated_fault
    db = db or get_db()
    ts = time.time()

    if is_linux_tc_supported():
        try:
            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"], capture_output=True)
        except Exception as e:
            logger.warning(f"Error resetting tc qdisc: {e}")

    prev_fault = _simulated_fault
    _simulated_fault = None

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="CLEARED",
            params_json=json.dumps({"interface": interface, "previous": prev_fault}),
        )
    )
    logger.info("Cleared all injected network faults.")
    return {"status": "CLEARED", "interface": interface, "timestamp": ts}
