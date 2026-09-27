"""
Adaptive Baseline Learner for Network Autopsy.
Learns running mean and standard deviation per metric per target,
persists to SQLite, updates adaptively via Exponential Moving Average (EMA),
and flags anomalies when a metric exceeds N standard deviations (default 3.0).
"""
import time
import math
import logging
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple

from storage.db import Database, get_db
from storage.models import Baseline
from engine.windowing import WindowFeatures

logger = logging.getLogger("network_autopsy.baseline")


@dataclass
class MetricAnomaly:
    metric_name: str
    target: str
    current_value: float
    baseline_mean: float
    baseline_stddev: float
    z_score: float
    is_anomaly: bool
    deviation_direction: str  # "HIGH" or "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdaptiveBaselineLearner:
    def __init__(
        self,
        db: Optional[Database] = None,
        warmup_samples: int = 20,
        z_threshold: float = 3.0,
        alpha_ema: float = 0.05,     # Weight for exponential moving average updates
    ):
        self.db = db or get_db()
        self.warmup_samples = warmup_samples
        self.z_threshold = z_threshold
        self.alpha_ema = alpha_ema

        # In-memory history for warm-up period: (metric, target) -> List[float]
        self._sample_history: Dict[Tuple[str, str], List[float]] = {}
        # In-memory cached baselines: (metric, target) -> Baseline
        self._cache: Dict[Tuple[str, str], Baseline] = {}
        self._load_baselines()

    def _load_baselines(self):
        try:
            persisted = self.db.get_all_baselines()
            for b in persisted:
                self._cache[(b.metric_name, b.target)] = b
        except Exception as e:
            logger.warning(f"Could not load existing baselines: {e}")

    def update_and_check(self, metric_name: str, target: str, value: float) -> MetricAnomaly:
        """
        Updates running baseline for (metric_name, target) and returns MetricAnomaly.
        """
        key = (metric_name, target)
        now = time.time()

        if key not in self._cache:
            # Check warm-up buffer
            if key not in self._sample_history:
                self._sample_history[key] = []
            self._sample_history[key].append(value)

            history = self._sample_history[key]
            if len(history) < self.warmup_samples:
                # Still in warm-up
                mean = sum(history) / len(history)
                # Compute sample stddev (min floor to avoid division by zero)
                variance = sum((x - mean) ** 2 for x in history) / max(len(history) - 1, 1)
                stddev = max(math.sqrt(variance), 0.5)

                return MetricAnomaly(
                    metric_name=metric_name,
                    target=target,
                    current_value=round(value, 2),
                    baseline_mean=round(mean, 2),
                    baseline_stddev=round(stddev, 2),
                    z_score=0.0,
                    is_anomaly=False,
                    deviation_direction="NORMAL",
                )
            else:
                # Completed warm-up: calculate initial baseline
                mean = sum(history) / len(history)
                variance = sum((x - mean) ** 2 for x in history) / (len(history) - 1)
                stddev = max(math.sqrt(variance), 1.0)
                b = Baseline(
                    metric_name=metric_name,
                    target=target,
                    mean=round(mean, 2),
                    stddev=round(stddev, 2),
                    last_updated=now,
                )
                self._cache[key] = b
                self.db.set_baseline(b)

        # Baseline exists: evaluate anomaly and update adaptively via EMA
        b = self._cache[key]
        std = max(b.stddev, 1.0)  # floor to avoid division by 0
        diff = value - b.mean
        z_score = diff / std

        is_anomaly = abs(z_score) >= self.z_threshold
        direction = "HIGH" if z_score > 0 else ("LOW" if z_score < 0 else "NORMAL")

        # Adaptively update baseline if NOT anomalous (or with smaller alpha if anomalous)
        effective_alpha = self.alpha_ema if not is_anomaly else (self.alpha_ema * 0.1)
        new_mean = (1 - effective_alpha) * b.mean + effective_alpha * value
        new_var = (1 - effective_alpha) * (b.stddev ** 2) + effective_alpha * ((value - new_mean) ** 2)
        new_stddev = max(math.sqrt(max(new_var, 0.01)), 0.5)

        b.mean = round(new_mean, 2)
        b.stddev = round(new_stddev, 2)
        b.last_updated = now
        self.db.set_baseline(b)

        return MetricAnomaly(
            metric_name=metric_name,
            target=target,
            current_value=round(value, 2),
            baseline_mean=b.mean,
            baseline_stddev=b.stddev,
            z_score=round(z_score, 2),
            is_anomaly=is_anomaly,
            deviation_direction=direction,
        )

    def evaluate_window(self, wf: WindowFeatures) -> List[MetricAnomaly]:
        """Evaluates all primary metrics in a window against their baselines."""
        anomalies: List[MetricAnomaly] = []

        metrics_to_check = [
            ("avg_latency", "overall", wf.avg_latency),
            ("jitter", "overall", wf.jitter),
            ("loss_pct", "overall", wf.loss_pct),
            ("gateway_latency", "gateway", wf.gateway_latency),
            ("gateway_loss", "gateway", wf.gateway_loss),
            ("external_latency", "external", wf.external_latency),
            ("external_loss", "external", wf.external_loss),
            ("dns_latency", "dns", wf.dns_latency),
            ("http_latency", "http", wf.http_latency),
            ("tcp_connect_latency", "tcp", wf.tcp_connect_latency),
            ("retrans_rate", "passive", wf.retrans_rate),
            ("dup_ack_rate", "passive", wf.dup_ack_rate),
            ("checksum_error_rate", "passive", wf.checksum_error_rate),
        ]

        for metric, target, val in metrics_to_check:
            anom = self.update_and_check(metric, target, val)
            if anom.is_anomaly:
                anomalies.append(anom)

        return anomalies
