"""
Validation Runner for Network Autopsy.
Runs automated trials across known fault injection types, evaluates the
diagnostic engine's accuracy, precision, recall, and confusion matrix against
ground truth, saves results to data/validation_results.json, and prints a
formatted console summary table.
"""
import os
import sys
import time
import json
import logging
import argparse
from typing import Dict, Any, List, Tuple
from collections import defaultdict

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import Database, get_db
from storage.models import ProbeResult, HopData, PacketEvent, Incident
from engine.windowing import WindowFeatures, WindowAggregator
from engine.baseline import AdaptiveBaselineLearner
from engine.rules import RuleClassifier
from engine.hop_confidence import HopConfidenceScorer
from engine.ml_classifier import NetworkFaultMLClassifier, get_ml_classifier
from engine.report_generator import ReportGenerator

logger = logging.getLogger("network_autopsy.validation_runner")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

RESULTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "validation_results.json"
)

EVALUATED_FAULT_TYPES = [
    "HEALTHY_NORMAL",
    "LOCAL_GATEWAY_CONGESTION",
    "UPSTREAM_ISP_FAULT",
    "DNS_FAILURE",
    "TARGET_SERVICE_DOWN",
    "NETWORK_CONGESTION_LOSSY_LINK",
    "PHYSICAL_CRC_CORRUPTION",
    "ROUTE_FLAP",
    "APPLICATION_LAYER_FAILURE",
]


class ValidationRunner:
    def __init__(self, trials_per_fault: int = 10):
        self.trials_per_fault = trials_per_fault
        self.db = Database(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "val_temp.db"))
        self.rules = RuleClassifier()
        self.hop_scorer = HopConfidenceScorer(self.db)
        self.ml_classifier = get_ml_classifier()
        self.baseline_learner = AdaptiveBaselineLearner(self.db, warmup_samples=5)

    def _generate_synthetic_window(self, fault_type: str, trial_idx: int) -> WindowFeatures:
        """Synthesizes a realistic window corresponding to the labeled fault type."""
        import random
        # Base healthy features
        wf = WindowFeatures(
            window_start=time.time() - 20.0,
            window_end=time.time(),
            duration_s=20.0,
            avg_latency=random.uniform(8.0, 20.0),
            max_latency=random.uniform(18.0, 32.0),
            jitter=random.uniform(0.8, 2.5),
            loss_pct=0.0,
            gateway_latency=random.uniform(1.5, 4.0),
            gateway_loss=0.0,
            external_latency=random.uniform(12.0, 25.0),
            external_loss=0.0,
            dns_latency=random.uniform(12.0, 35.0),
            dns_loss_pct=0.0,
            http_latency=random.uniform(25.0, 50.0),
            http_ttfb=15.0,
            http_status_code=200,
            http_loss_pct=0.0,
            tcp_connect_latency=random.uniform(8.0, 22.0),
            tcp_connect_loss_pct=0.0,
            retrans_count=0,
            dup_ack_count=0,
            checksum_errors=0,
            hop_count=9,
            hop1_rtt=2.5,
            hop1_loss=0.0,
            route_changed=False,
        )

        if fault_type == "LOCAL_GATEWAY_CONGESTION":
            wf.gateway_latency = random.uniform(85.0, 180.0)
            wf.gateway_loss = random.uniform(25.0, 55.0)
            wf.hop1_rtt = wf.gateway_latency
            wf.hop1_loss = wf.gateway_loss
            wf.avg_latency = wf.gateway_latency + 15.0
            wf.jitter = random.uniform(15.0, 35.0)

        elif fault_type == "UPSTREAM_ISP_FAULT":
            wf.gateway_latency = 2.0
            wf.gateway_loss = 0.0
            wf.hop1_rtt = 2.0
            wf.hop1_loss = 0.0
            wf.external_latency = random.uniform(180.0, 350.0)
            wf.external_loss = random.uniform(30.0, 65.0)
            wf.avg_latency = wf.external_latency
            wf.loss_pct = wf.external_loss

        elif fault_type == "DNS_FAILURE":
            wf.dns_latency = random.uniform(1500.0, 2800.0)
            wf.dns_loss_pct = 100.0
            wf.external_loss = 0.0

        elif fault_type == "TARGET_SERVICE_DOWN":
            wf.tcp_connect_loss_pct = 100.0
            wf.tcp_connect_latency = 0.0
            wf.loss_pct = 0.0  # ICMP still works

        elif fault_type == "NETWORK_CONGESTION_LOSSY_LINK":
            wf.retrans_count = random.randint(8, 24)
            wf.dup_ack_count = random.randint(5, 18)
            wf.retrans_rate = wf.retrans_count / 20.0
            wf.dup_ack_rate = wf.dup_ack_count / 20.0
            wf.loss_pct = random.uniform(12.0, 28.0)
            wf.jitter = random.uniform(10.0, 25.0)

        elif fault_type == "PHYSICAL_CRC_CORRUPTION":
            wf.checksum_errors = random.randint(3, 10)
            wf.checksum_error_rate = wf.checksum_errors / 20.0
            wf.loss_pct = random.uniform(5.0, 15.0)

        elif fault_type == "ROUTE_FLAP":
            wf.route_changed = True
            wf.hop_count = random.choice([6, 13])
            wf.jitter = random.uniform(15.0, 45.0)

        elif fault_type == "APPLICATION_LAYER_FAILURE":
            wf.tcp_connect_loss_pct = 0.0
            wf.http_status_code = random.choice([500, 502, 503])
            wf.http_loss_pct = 100.0
            wf.http_latency = random.uniform(2500.0, 3500.0)

        return wf

    def _map_diagnosis_to_class(self, rule_name: str, ml_cause: str) -> str:
        """Standardizes diagnosis string to one of the 9 canonical classes."""
        r = rule_name.lower()
        if "gateway" in r or "wi-fi" in r:
            return "LOCAL_GATEWAY_CONGESTION"
        elif "hop n" in r or "upstream" in r or "isp" in r:
            return "UPSTREAM_ISP_FAULT"
        elif "dns" in r:
            return "DNS_FAILURE"
        elif "service down" in r or "firewall" in r or "port" in r:
            return "TARGET_SERVICE_DOWN"
        elif "lossy link" in r or "congestion" in r:
            return "NETWORK_CONGESTION_LOSSY_LINK"
        elif "physical" in r or "checksum" in r or "corruption" in r:
            return "PHYSICAL_CRC_CORRUPTION"
        elif "route flap" in r or "path change" in r:
            return "ROUTE_FLAP"
        elif "application" in r:
            return "APPLICATION_LAYER_FAILURE"
        elif ml_cause in EVALUATED_FAULT_TYPES and ml_cause != "UNKNOWN":
            return ml_cause
        return "HEALTHY_NORMAL"

    def run_validation(self) -> Dict[str, Any]:
        """Runs the validation suite across all fault types and computes metrics."""
        print("\n" + "=" * 76)
        print("    NETWORK AUTOPSY - FAULT INJECTION & DIAGNOSIS VALIDATION SUITE")
        print("=" * 76)
        print(f"Running {self.trials_per_fault} automated trials per fault category across {len(EVALUATED_FAULT_TYPES)} classes...")

        # Confusion Matrix: confusion[actual][predicted] = count
        confusion: Dict[str, Dict[str, int]] = {
            act: {pred: 0 for pred in EVALUATED_FAULT_TYPES}
            for act in EVALUATED_FAULT_TYPES
        }

        total_trials = 0
        correct_predictions = 0

        for fault_type in EVALUATED_FAULT_TYPES:
            for trial_idx in range(self.trials_per_fault):
                total_trials += 1
                wf = self._generate_synthetic_window(fault_type, trial_idx)

                # Run Rule Classifier
                rule_diagnoses = self.rules.evaluate(wf)
                primary_rule = rule_diagnoses[0].rule_name if rule_diagnoses else ""

                # Run ML Classifier
                ml_pred_class, ml_conf, _ = self.ml_classifier.predict(wf)

                # Determine final predicted class
                pred_class = self._map_diagnosis_to_class(primary_rule, ml_pred_class)

                confusion[fault_type][pred_class] += 1
                if pred_class == fault_type:
                    correct_predictions += 1

        overall_accuracy = correct_predictions / total_trials if total_trials > 0 else 0.0

        # Compute per-class Precision, Recall, F1
        per_class_metrics: Dict[str, Dict[str, float]] = {}
        for c in EVALUATED_FAULT_TYPES:
            tp = confusion[c][c]
            fp = sum(confusion[other][c] for other in EVALUATED_FAULT_TYPES if other != c)
            fn = sum(confusion[c][other] for other in EVALUATED_FAULT_TYPES if other != c)

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

            per_class_metrics[c] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1_score": round(f1, 4),
                "support": self.trials_per_fault,
            }

        results = {
            "timestamp": time.time(),
            "total_trials": total_trials,
            "trials_per_fault": self.trials_per_fault,
            "overall_accuracy": round(overall_accuracy, 4),
            "per_class_metrics": per_class_metrics,
            "confusion_matrix": confusion,
        }

        # Save to data/validation_results.json
        os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
        with open(RESULTS_PATH, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        # Print formatted summary table
        self._print_summary_table(results)

        # Cleanup temporary DB
        try:
            if os.path.exists(self.db.db_path):
                os.remove(self.db.db_path)
        except Exception:
            pass

        return results

    def _print_summary_table(self, res: Dict[str, Any]):
        print("\n" + "-" * 76)
        print(f"{'FAULT CATEGORY / GROUND TRUTH':<35} | {'PRECISION':<10} | {'RECALL':<8} | {'F1-SCORE':<8}")
        print("-" * 76)
        for c, m in res["per_class_metrics"].items():
            name_display = c.replace("_", " ")[:34]
            print(f"{name_display:<35} | {m['precision']*100:>8.1f}% | {m['recall']*100:>6.1f}% | {m['f1_score']:>8.3f}")
        print("-" * 76)
        print(f"OVERALL DIAGNOSTIC ACCURACY: {res['overall_accuracy']*100:.2f}% ({res['total_trials']} total trials)")
        print(f"Results persisted to: {RESULTS_PATH}")
        print("=" * 76 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Autopsy Validation Suite")
    parser.add_argument("--trials", type=int, default=10, help="Number of trials per fault type (default: 10)")
    args = parser.parse_args()

    runner = ValidationRunner(trials_per_fault=args.trials)
    runner.run_validation()
