"""
Machine Learning Classifier Module for Network Autopsy.
Deploys an interpretable DecisionTreeClassifier (max_depth=6) for runtime secondary
confirmation, while training a RandomForestClassifier in parallel purely for
validation and accuracy comparison.
Exports:
- Human-readable decision tree rules to data/decision_tree_rules.txt
- Model performance comparison to data/ml_comparison.json
"""
import os
import json
import logging
import numpy as np
from typing import Dict, Any, List, Optional, Tuple

from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

from engine.windowing import WindowFeatures

logger = logging.getLogger("network_autopsy.ml_classifier")

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
RULES_PATH = os.path.join(DATA_DIR, "decision_tree_rules.txt")
COMPARISON_PATH = os.path.join(DATA_DIR, "ml_comparison.json")

FAULT_CLASSES = [
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


class NetworkFaultMLClassifier:
    def __init__(self, max_depth: int = 6):
        self.max_depth = max_depth
        self.dt_model: Optional[DecisionTreeClassifier] = None
        self.rf_model: Optional[RandomForestClassifier] = None
        self.is_trained = False
        self.feature_names = WindowFeatures.feature_names()
        self.classes = FAULT_CLASSES
        self.class_to_idx = {name: i for i, name in enumerate(self.classes)}
        self.idx_to_class = {i: name for i, name in enumerate(self.classes)}
        self.latest_metrics: Dict[str, Any] = {}

    def generate_synthetic_dataset(self, samples_per_class: int = 150) -> Tuple[np.ndarray, np.ndarray]:
        """
        Generates realistic training data reflecting standard network operations
        and each fault mode based on network telemetry parameters.
        """
        X_list = []
        y_list = []
        np.random.seed(42)

        for class_idx, class_name in enumerate(self.classes):
            for _ in range(samples_per_class):
                # Baseline healthy features
                avg_lat = np.random.uniform(5.0, 25.0)
                max_lat = avg_lat + np.random.uniform(2.0, 15.0)
                jitter = np.random.uniform(0.5, 3.0)
                loss_pct = np.random.choice([0.0, 0.0, 0.0, 1.0])
                gw_lat = np.random.uniform(1.0, 5.0)
                gw_loss = 0.0
                ext_lat = avg_lat
                ext_loss = loss_pct
                dns_lat = np.random.uniform(10.0, 45.0)
                dns_loss = 0.0
                http_lat = np.random.uniform(25.0, 80.0)
                http_ttfb = http_lat * 0.4
                http_status = 200
                http_loss = 0.0
                tcp_lat = np.random.uniform(8.0, 30.0)
                tcp_loss = 0.0
                retrans = int(np.random.choice([0, 0, 1]))
                dup_acks = int(np.random.choice([0, 0, 0]))
                chk_errs = 0
                retrans_rate = retrans / 20.0
                dup_ack_rate = dup_acks / 20.0
                chk_rate = 0.0
                hop_count = int(np.random.choice([8, 9, 10]))
                hop1_rtt = gw_lat
                hop1_loss = 0.0
                route_changed = 0.0

                # Inject fault-specific feature distributions
                if class_name == "LOCAL_GATEWAY_CONGESTION":
                    gw_lat = np.random.uniform(80.0, 300.0)
                    gw_loss = np.random.uniform(20.0, 60.0)
                    hop1_rtt = gw_lat
                    hop1_loss = gw_loss
                    avg_lat = gw_lat + np.random.uniform(10.0, 40.0)
                    max_lat = avg_lat + 50.0
                    jitter = np.random.uniform(15.0, 50.0)
                    loss_pct = gw_loss

                elif class_name == "UPSTREAM_ISP_FAULT":
                    gw_lat = np.random.uniform(1.0, 5.0)
                    gw_loss = 0.0
                    hop1_rtt = gw_lat
                    hop1_loss = 0.0
                    ext_lat = np.random.uniform(180.0, 450.0)
                    ext_loss = np.random.uniform(25.0, 75.0)
                    avg_lat = ext_lat
                    loss_pct = ext_loss

                elif class_name == "DNS_FAILURE":
                    dns_lat = np.random.uniform(1000.0, 3000.0)
                    dns_loss = np.random.choice([80.0, 100.0])
                    ext_loss = 0.0
                    ext_lat = np.random.uniform(10.0, 30.0)

                elif class_name == "TARGET_SERVICE_DOWN":
                    tcp_loss = 100.0
                    tcp_lat = 0.0
                    loss_pct = 0.0  # ICMP ping still works
                    http_loss = 100.0

                elif class_name == "NETWORK_CONGESTION_LOSSY_LINK":
                    retrans = int(np.random.uniform(8, 30))
                    dup_acks = int(np.random.uniform(6, 25))
                    retrans_rate = retrans / 20.0
                    dup_ack_rate = dup_acks / 20.0
                    loss_pct = np.random.uniform(10.0, 35.0)
                    jitter = np.random.uniform(12.0, 40.0)

                elif class_name == "PHYSICAL_CRC_CORRUPTION":
                    chk_errs = int(np.random.uniform(3, 15))
                    chk_rate = chk_errs / 20.0
                    loss_pct = np.random.uniform(5.0, 25.0)

                elif class_name == "ROUTE_FLAP":
                    route_changed = 1.0
                    hop_count = int(np.random.choice([6, 14]))
                    jitter = np.random.uniform(15.0, 60.0)

                elif class_name == "APPLICATION_LAYER_FAILURE":
                    tcp_loss = 0.0  # TCP connection works
                    http_status = int(np.random.choice([500, 502, 503, 0]))
                    http_loss = 100.0
                    http_lat = np.random.uniform(2000.0, 4000.0)

                vector = [
                    avg_lat, max_lat, jitter, loss_pct,
                    gw_lat, gw_loss, ext_lat, ext_loss,
                    dns_lat, dns_loss,
                    http_lat, http_ttfb, float(http_status), http_loss,
                    tcp_lat, tcp_loss,
                    float(retrans), float(dup_acks), float(chk_errs),
                    retrans_rate, dup_ack_rate, chk_rate,
                    float(hop_count), hop1_rtt, hop1_loss,
                    route_changed,
                ]
                X_list.append(vector)
                y_list.append(class_idx)

        return np.array(X_list), np.array(y_list)

    def train_models(self, X: Optional[np.ndarray] = None, y: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        Trains DecisionTree (deployed) and RandomForest (validation benchmark).
        Saves rules text and comparison JSON.
        """
        if X is None or y is None or len(X) < 50:
            X, y = self.generate_synthetic_dataset(samples_per_class=180)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )

        # 1. Train Decision Tree (deployed, interpretability-optimized)
        dt = DecisionTreeClassifier(max_depth=self.max_depth, random_state=42)
        dt.fit(X_train, y_train)
        y_pred_dt = dt.predict(X_test)

        # 2. Train Random Forest (validation baseline)
        rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        rf.fit(X_train, y_train)
        y_pred_rf = rf.predict(X_test)

        # Metrics computation
        dt_acc = float(accuracy_score(y_test, y_pred_dt))
        dt_prec = float(precision_score(y_test, y_pred_dt, average="weighted", zero_division=0))
        dt_rec = float(recall_score(y_test, y_pred_dt, average="weighted", zero_division=0))
        dt_f1 = float(f1_score(y_test, y_pred_dt, average="weighted", zero_division=0))

        rf_acc = float(accuracy_score(y_test, y_pred_rf))
        rf_prec = float(precision_score(y_test, y_pred_rf, average="weighted", zero_division=0))
        rf_rec = float(recall_score(y_test, y_pred_rf, average="weighted", zero_division=0))
        rf_f1 = float(f1_score(y_test, y_pred_rf, average="weighted", zero_division=0))

        self.dt_model = dt
        self.rf_model = rf
        self.is_trained = True

        os.makedirs(DATA_DIR, exist_ok=True)

        # Export human-readable decision tree rules
        tree_text = export_text(dt, feature_names=self.feature_names)
        with open(RULES_PATH, "w", encoding="utf-8") as f:
            f.write("=== NETWORK AUTOPSY - DEPLOYED DECISION TREE RULES ===\n")
            f.write(f"Max Depth: {self.max_depth}\n")
            f.write(f"Classes: {', '.join(self.classes)}\n\n")
            f.write(tree_text)

        # Prepare comparison report
        comparison = {
            "deployed_model": {
                "name": "DecisionTreeClassifier",
                "role": "Deployed runtime model (interpretability-optimized)",
                "max_depth": self.max_depth,
                "accuracy": round(dt_acc, 4),
                "precision": round(dt_prec, 4),
                "recall": round(dt_rec, 4),
                "f1_score": round(dt_f1, 4),
            },
            "validation_baseline": {
                "name": "RandomForestClassifier",
                "role": "Validation benchmark (accuracy comparison only)",
                "n_estimators": 100,
                "accuracy": round(rf_acc, 4),
                "precision": round(rf_prec, 4),
                "recall": round(rf_rec, 4),
                "f1_score": round(rf_f1, 4),
            },
            "summary": (
                f"Decision Tree achieved {dt_acc*100:.1f}% accuracy while providing 100% transparent "
                f"if-then rules exportable for viva and post-mortem analysis. Random Forest achieved "
                f"{rf_acc*100:.1f}% accuracy as the theoretical upper-bound benchmark."
            ),
            "classes": self.classes,
        }

        with open(COMPARISON_PATH, "w", encoding="utf-8") as f:
            json.dump(comparison, f, indent=2)

        self.latest_metrics = comparison
        logger.info(f"ML models trained successfully. DT accuracy={dt_acc:.4f}, RF accuracy={rf_acc:.4f}")
        return comparison

    def predict(self, features: WindowFeatures) -> Tuple[str, float, Dict[str, float]]:
        """
        Uses deployed Decision Tree to predict fault type and secondary confidence score.
        Returns: (predicted_class_name, confidence_score, probabilities_dict)
        """
        if not self.is_trained or self.dt_model is None:
            self.train_models()

        vec = np.array(features.to_feature_vector()).reshape(1, -1)
        pred_idx = int(self.dt_model.predict(vec)[0])
        pred_probs = self.dt_model.predict_proba(vec)[0]

        pred_class = self.idx_to_class.get(pred_idx, "UNKNOWN")
        confidence = float(pred_probs[pred_idx])

        prob_dict = {
            self.idx_to_class[i]: round(float(p), 4)
            for i, p in enumerate(pred_probs)
            if i < len(self.classes)
        }

        return pred_class, round(confidence, 3), prob_dict


# Singleton instance
_ml_classifier_instance: Optional[NetworkFaultMLClassifier] = None


def get_ml_classifier() -> NetworkFaultMLClassifier:
    global _ml_classifier_instance
    if _ml_classifier_instance is None:
        _ml_classifier_instance = NetworkFaultMLClassifier()
        _ml_classifier_instance.train_models()
    return _ml_classifier_instance
