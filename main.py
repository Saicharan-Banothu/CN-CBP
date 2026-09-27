"""
Main Entry Point for Network Autopsy.
Wires together:
1. Storage Layer (SQLite database initialization)
2. Active Probe Scheduler (runs ping, traceroute, tcp, dns, http probes)
3. Passive Capture Agent (Scapy sniffer with fallback)
4. Diagnosis Engine loop (Windowing -> Baseline -> Rules -> Hop Confidence -> ML -> Reports)
5. FastAPI Web Application and Dashboard Server
"""
import os
import sys
import time
import yaml
import signal
import logging
import threading
import uvicorn
from typing import Dict, Any

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
import webapp.server as web_server

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

        # 2. Initialize Diagnosis Engine Components
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

        # 3. Initialize Active Probes Scheduler
        agent_cfg = config.get("agent", {})
        gateway_ip = _get_default_gateway_ip()

        # Replace "auto_gateway" placeholders
        raw_pings = agent_cfg.get("ping_targets", ["auto_gateway", "8.8.8.8", "1.1.1.1"])
        ping_targets = [gateway_ip if t == "auto_gateway" else t for t in raw_pings]

        raw_tcps = agent_cfg.get("tcp_targets", [{"target": "auto_gateway", "port": 80}])
        tcp_targets = []
        for item in raw_tcps:
            t = gateway_ip if item["target"] == "auto_gateway" else item["target"]
            tcp_targets.append({"target": t, "port": item["port"]})

        self.probe_scheduler = ProbeScheduler(
            db=self.db,
            interval_seconds=agent_cfg.get("probe_interval_seconds", 10.0),
            ping_targets=ping_targets,
            traceroute_targets=agent_cfg.get("traceroute_targets", ["8.8.8.8"]),
            tcp_targets=tcp_targets,
            dns_targets=agent_cfg.get("dns_targets"),
            http_targets=agent_cfg.get("http_targets"),
        )

        # 4. Initialize Passive Capture Agent
        sniff_cfg = agent_cfg.get("sniffer", {})
        self.passive_capture = PassiveCaptureAgent(
            db=self.db,
            interface=sniff_cfg.get("interface"),
            bpf_filter=sniff_cfg.get("bpf_filter", "ip or arp"),
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

    def _diagnosis_loop(self):
        """Background loop continuously evaluating window features and generating incident reports."""
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

                # If rule diagnoses fired or baseline anomalies are severe
                if rule_diagnoses or anomalies or (ml_cause != "HEALTHY_NORMAL" and ml_conf > 0.70):
                    inc = self.report_gen.generate_report(
                        features=features,
                        rules=rule_diagnoses,
                        hop_result=hop_res,
                        ml_prediction=ml_eval,
                        anomalies=anomalies,
                    )
                    logger.warning(
                        f"🚨 NETWORK INCIDENT DETECTED #{inc.id}: {inc.probable_cause} "
                        f"[Layer: {inc.affected_layer} | Conf: {(inc.confidence_score*100):.0f}% | Hop: {inc.hop_location}]"
                    )

            except Exception as e:
                logger.error(f"Error in diagnosis evaluation loop: {e}", exc_info=True)

            # Sleep in slices for responsive shutdown
            for _ in range(int(interval * 5)):
                if not self._running:
                    break
                time.sleep(0.2)

    def start(self):
        logger.info("Starting Network Autopsy System components...")
        self._running = True

        # Pre-seed with one initial probe cycle so telemetry is immediately visible on launch
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

        logger.info("All background engine and probe tasks active.")

    def stop(self):
        logger.info("Shutting down Network Autopsy System...")
        self._running = False
        self.probe_scheduler.stop()
        self.passive_capture.stop()
        if self._diag_thread and self._diag_thread.is_alive():
            self._diag_thread.join(timeout=2.0)
        logger.info("Shutdown complete.")


def main():
    config = load_config()
    system = NetworkAutopsySystem(config)
    system.start()

    server_cfg = config.get("server", {})
    host = server_cfg.get("host", "127.0.0.1")
    port = server_cfg.get("port", 8000)

    print("\n" + "=" * 70)
    print("      🛰️   NETWORK AUTOPSY SERVER IS LIVE AND MONITORING")
    print(f"      Dashboard URL: http://{host}:{port}/")
    print(f"      API Docs:      http://{host}:{port}/docs")
    print("=" * 70 + "\n")

    try:
        uvicorn.run(web_server.app, host=host, port=port, log_level="warning")
    except (KeyboardInterrupt, SystemExit):
        logger.info("Server interrupted by user.")
    finally:
        system.stop()


if __name__ == "__main__":
    main()
