"""
Main Entry Point for Network Autopsy.
Wires together:
1. Storage Layer (SQLite WAL mode database initialization)
2. Safe Fault Proxy (Local ControlledNetworkTarget on 127.0.0.1:8085)
3. Active Probe Scheduler (runs ping, traceroute, tcp, dns, http probes)
4. Passive Capture Agent (Scapy packet analyzer with fallback)
5. Diagnosis Engine loop (Windowing -> Adaptive Baselines -> Rules -> Hop Confidence -> ML -> Incident Lifecycle)
6. FastAPI Web Application and Dashboard Server
"""
import os
import sys
import time
import yaml
import signal
import logging
import threading
import uvicorn
from typing import Dict, Any, Optional

from storage.db import Database, get_db
from agent.probe_scheduler import ProbeScheduler
from agent.passive_capture import PassiveCaptureAgent
from agent.active_probes import _get_default_gateway_ip
from engine.windowing import WindowAggregator
from engine.baseline import AdaptiveBaselineLearner
from engine.rules import RuleClassifier
from engine.hop_confidence import HopConfidenceScorer
from engine.ml_classifier import get_ml_classifier
from engine.report_generator import ReportGenerator
from sandbox.local_fault_proxy import start_local_fault_proxy, stop_local_fault_proxy
from sandbox.fault_injection import SafeFaultController
import webapp.server as web_server

# Reconfigure stdout/stderr to utf-8 for Windows console resilience
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("network_autopsy.main")

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")


def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    return {}


class NetworkAutopsySystem:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._running = False
        self._diag_thread: Optional[threading.Thread] = None

        # 1. Initialize Storage
        db_path = config.get("storage", {}).get("db_path", "data/autopsy.db")
        self.db = get_db(db_path)
        logger.info(f"Initialized SQLite database at {self.db.db_path}")

        # 2. Start Safe Local Network Fault Proxy
        self.proxy_target = start_local_fault_proxy(port=8085)
        self.fault_controller = SafeFaultController(db=self.db)

        # 3. Initialize Diagnosis Engine Components
        engine_cfg = config.get("engine", {})
        win_duration = engine_cfg.get("window_duration_seconds", 20.0)
        self.aggregator = WindowAggregator(self.db, window_seconds=win_duration)

        base_cfg = engine_cfg.get("baseline", {})
        self.baseline_learner = AdaptiveBaselineLearner(
            self.db,
            warmup_samples=base_cfg.get("warmup_samples", 15),
            z_threshold=base_cfg.get("z_threshold", 3.0),
            alpha_ema=base_cfg.get("alpha_ema", 0.05),
        )

        self.rules_classifier = RuleClassifier()
        self.hop_scorer = HopConfidenceScorer(self.db)
        self.ml_classifier = get_ml_classifier()
        self.report_gen = ReportGenerator(self.db)

        # 4. Initialize Active Probes Scheduler
        agent_cfg = config.get("agent", {})
        gateway_ip = _get_default_gateway_ip()

        raw_pings = agent_cfg.get("ping_targets", ["auto_gateway", "8.8.8.8", "1.1.1.1"])
        ping_targets = [gateway_ip if t == "auto_gateway" else t for t in raw_pings]

        raw_tcps = agent_cfg.get("tcp_targets", [{"target": "auto_gateway", "port": 80}])
        tcp_targets = []
        for item in raw_tcps:
            t = gateway_ip if item["target"] == "auto_gateway" else item["target"]
            tcp_targets.append({"target": t, "port": item["port"]})

        # Ensure our controlled socket proxy target is included in TCP probes
        has_proxy_target = any(
            t.get("target") == "127.0.0.1" and t.get("port") == 8085 for t in tcp_targets
        )
        if not has_proxy_target:
            tcp_targets.append({"target": "127.0.0.1", "port": 8085})

        # 4. Initialize Passive Capture Agent
        sniff_cfg = agent_cfg.get("sniffer", {})
        self.passive_capture = PassiveCaptureAgent(
            db=self.db,
            interface=sniff_cfg.get("interface"),
            bpf_filter=sniff_cfg.get("bpf_filter", "ip or arp"),
        )

        # 5. Initialize Active Probes Scheduler
        self.probe_scheduler = ProbeScheduler(
            db=self.db,
            interval_seconds=agent_cfg.get("probe_interval_seconds", 10.0),
            ping_targets=ping_targets,
            traceroute_targets=agent_cfg.get("traceroute_targets", ["8.8.8.8"]),
            tcp_targets=tcp_targets,
            dns_targets=agent_cfg.get("dns_targets"),
            http_targets=agent_cfg.get("http_targets"),
            passive_capture=self.passive_capture,
        )

        # Connect references to FastAPI server module
        web_server.db = self.db
        web_server.aggregator = self.aggregator
        web_server.baseline_learner = self.baseline_learner
        web_server.rules_classifier = self.rules_classifier
        web_server.hop_scorer = self.hop_scorer
        web_server.ml_classifier = self.ml_classifier
        web_server.report_gen = self.report_gen
        web_server.probe_scheduler_ref = self.probe_scheduler
        web_server.passive_capture_ref = self.passive_capture
        web_server.fault_controller = self.fault_controller

    def _diagnosis_loop(self):
        """Background loop continuously evaluating window features and managing incident lifecycles."""
        interval = self.config.get("engine", {}).get("eval_interval_seconds", 10.0)
        logger.info(f"Diagnosis Engine background loop started (interval={interval}s)")

        while self._running:
            try:
                features = self.aggregator.aggregate_current_window()
                anomalies = self.baseline_learner.evaluate_window(features)
                hop_res = self.hop_scorer.evaluate_hops(features)
                rule_diagnoses = self.rules_classifier.evaluate(features, anomalies, hop_res.to_dict())

                ml_cause, ml_conf, ml_probs = self.ml_classifier.predict(features)
                ml_eval = {
                    "predicted_class": ml_cause,
                    "confidence": ml_conf,
                    "probabilities": ml_probs,
                }

                # 1. Recovery Detection: Transition ongoing incidents back to RESOLVED when metrics return to baseline
                resolved_incidents = self.report_gen.check_recovery_for_active_incidents(
                    features=features,
                    anomalies=anomalies,
                    rules=rule_diagnoses,
                )
                for res_inc in resolved_incidents:
                    logger.info(
                        f"[RESOLVED] INCIDENT #{res_inc.id}: {res_inc.probable_cause} (Duration: {res_inc.duration_s:.1f}s)"
                    )

                # 2. Incident Lifecycle: Create or update ongoing incident with deduplication key
                if rule_diagnoses or anomalies or (ml_cause != "HEALTHY_NORMAL" and ml_conf > 0.70):
                    inc = self.report_gen.generate_or_update_incident(
                        features=features,
                        rules=rule_diagnoses,
                        hop_result=hop_res,
                        ml_prediction=ml_eval,
                        anomalies=anomalies,
                    )
                    status_tag = "[ALERT]" if inc.status == "DETECTED" else "[WARN]"
                    logger.warning(
                        f"{status_tag} NETWORK INCIDENT #{inc.id} [{inc.status}]: {inc.probable_cause} "
                        f"[Layer: {inc.affected_layer} | Conf: {(inc.confidence_score*100):.0f}% | Hop: {inc.hop_location} | Occurrences: {inc.occurrence_count}]"
                    )

            except Exception as e:
                logger.error(f"Error in diagnosis evaluation loop: {e}", exc_info=True)

            # Sleep in small slices for responsive shutdown
            for _ in range(int(interval * 5)):
                if not self._running:
                    break
                time.sleep(0.2)

    def start(self):
        logger.info("Starting Network Autopsy System components...")
        self._running = True

        # Pre-seed initial probe cycle
        try:
            logger.info("Executing initial network probe cycle...")
            self.probe_scheduler.run_cycle_now()
        except Exception as e:
            logger.warning(f"Initial probe cycle had warnings: {e}")

        # Start probe scheduler
        self.probe_scheduler.start()

        # Start passive sniffer
        self.passive_capture.start()

        # Start diagnosis engine evaluation thread
        self._diag_thread = threading.Thread(
            target=self._diagnosis_loop, daemon=True, name="DiagnosisEngineLoop"
        )
        self._diag_thread.start()

        logger.info("All background engine, proxy, and probe tasks active.")

    def stop(self):
        logger.info("Shutting down Network Autopsy System...")
        self._running = False
        self.probe_scheduler.stop()
        self.passive_capture.stop()
        self.fault_controller.cleanup_all_faults()
        stop_local_fault_proxy()
        if self._diag_thread and self._diag_thread.is_alive():
            self._diag_thread.join(timeout=2.0)
        logger.info("Shutdown complete and all faults safely cleared.")


def main():
    config = load_config()
    system = NetworkAutopsySystem(config)
    system.start()

    server_cfg = config.get("server", {})
    host = os.environ.get("HOST", server_cfg.get("host", "0.0.0.0"))
    port = int(os.environ.get("PORT", server_cfg.get("port", 8000)))

    print("\n" + "=" * 75)
    print("      [*] NETWORK AUTOPSY PLATFORM IS LIVE AND MONITORING")
    print(f"      Dashboard:      http://{host}:{port}/")
    print(f"      Validation Lab: http://{host}:{port}/static/dashboard.html#validation")
    print(f"      API Swagger:    http://{host}:{port}/docs")
    print("=" * 75 + "\n")

    try:
        uvicorn.run(web_server.app, host=host, port=port, log_level="warning")
    except (KeyboardInterrupt, SystemExit):
        logger.info("Server interrupted by user.")
    finally:
        system.stop()


if __name__ == "__main__":
    main()
