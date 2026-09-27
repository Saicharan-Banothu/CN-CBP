"""
Service Killer Module for Network Autopsy.
Simulates:
- DNS-down (pointing resolution at unreachable IP or dropping port 53)
- HTTP-down (instructing local demo server to return 503/fail, or terminating daemon)
Logs all actions to SQLite `fault_labels` table.
"""
import time
import json
import logging
from typing import Dict, Any, Optional

from storage.db import Database, get_db
from storage.models import FaultLabel

logger = logging.getLogger("network_autopsy.service_killer")

# In-memory service state flags accessible by scheduler and local server
SERVICE_STATES = {
    "dns_healthy": True,
    "dns_override_ip": None,
    "http_healthy": True,
    "http_error_code": 200,
}


def kill_dns_service(unreachable_ip: str = "192.0.2.53", db: Optional[Database] = None) -> Dict[str, Any]:
    """Simulates DNS resolution failure by redirecting DNS queries to an unreachable address."""
    db = db or get_db()
    ts = time.time()
    SERVICE_STATES["dns_healthy"] = False
    SERVICE_STATES["dns_override_ip"] = unreachable_ip

    params = {"target_override": unreachable_ip, "mode": "UNREACHABLE_IP"}
    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="DNS_FAILURE",
            params_json=json.dumps(params),
        )
    )
    logger.info(f"Simulated DNS Failure: DNS resolver redirected to {unreachable_ip}")
    return {"status": "DNS_KILLED", "unreachable_ip": unreachable_ip, "timestamp": ts}


def restore_dns_service(db: Optional[Database] = None) -> Dict[str, Any]:
    """Restores standard DNS resolution."""
    db = db or get_db()
    ts = time.time()
    SERVICE_STATES["dns_healthy"] = True
    SERVICE_STATES["dns_override_ip"] = None

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="DNS_RESTORED",
            params_json=json.dumps({"status": "RESTORED"}),
        )
    )
    logger.info("Restored DNS service to healthy operational state.")
    return {"status": "DNS_RESTORED", "timestamp": ts}


def kill_http_service(status_code: int = 503, db: Optional[Database] = None) -> Dict[str, Any]:
    """Simulates HTTP service failure / crash on demo endpoint."""
    db = db or get_db()
    ts = time.time()
    SERVICE_STATES["http_healthy"] = False
    SERVICE_STATES["http_error_code"] = status_code

    params = {"status_code": status_code, "mode": "APPLICATION_5XX_FAILURE"}
    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="HTTP_SERVICE_DOWN",
            params_json=json.dumps(params),
        )
    )
    logger.info(f"Simulated HTTP Service Down: Endpoint now returning {status_code}")
    return {"status": "HTTP_KILLED", "error_code": status_code, "timestamp": ts}


def restore_http_service(db: Optional[Database] = None) -> Dict[str, Any]:
    """Restores HTTP service health."""
    db = db or get_db()
    ts = time.time()
    SERVICE_STATES["http_healthy"] = True
    SERVICE_STATES["http_error_code"] = 200

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="HTTP_RESTORED",
            params_json=json.dumps({"status": "RESTORED"}),
        )
    )
    logger.info("Restored HTTP service to healthy operational state (HTTP 200).")
    return {"status": "HTTP_RESTORED", "timestamp": ts}
