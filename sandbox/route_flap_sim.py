"""
Route Flap Simulator for Network Autopsy.
Simulates routing table oscillation and path changes by alternating
active traceroute targets / intermediate hop topologies.
Logs each route change event to SQLite `fault_labels`.
"""
import time
import json
import logging
from typing import Dict, Any, Optional

from storage.db import Database, get_db
from storage.models import FaultLabel

logger = logging.getLogger("network_autopsy.route_flap_sim")

ROUTE_SIM_STATE = {
    "is_flapping": False,
    "alternate_path": False,
}


def trigger_route_flap(db: Optional[Database] = None) -> Dict[str, Any]:
    """Toggles route flap simulation state to trigger path changes between consecutive traceroutes."""
    db = db or get_db()
    ts = time.time()
    ROUTE_SIM_STATE["is_flapping"] = True
    ROUTE_SIM_STATE["alternate_path"] = not ROUTE_SIM_STATE["alternate_path"]

    params = {
        "is_flapping": True,
        "alternate_path": ROUTE_SIM_STATE["alternate_path"],
        "simulated_hops_delta": 3,
    }
    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="ROUTE_FLAP",
            params_json=json.dumps(params),
        )
    )
    logger.info("Triggered simulated route flap / path oscillation.")
    return {"status": "ROUTE_FLAP_ACTIVE", "params": params, "timestamp": ts}


def clear_route_flap(db: Optional[Database] = None) -> Dict[str, Any]:
    """Resets route flap simulation state."""
    db = db or get_db()
    ts = time.time()
    ROUTE_SIM_STATE["is_flapping"] = False
    ROUTE_SIM_STATE["alternate_path"] = False

    db.insert_fault_label(
        FaultLabel(
            timestamp=ts,
            injected_fault_type="ROUTE_FLAP_CLEARED",
            params_json=json.dumps({"status": "RESTORED"}),
        )
    )
    logger.info("Cleared route flap simulation.")
    return {"status": "ROUTE_FLAP_CLEARED", "timestamp": ts}
