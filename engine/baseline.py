"""
Adaptive Baseline Learner for Network Autopsy.
Learns running mean, standard deviation, median, p95, and percentiles per metric per target.
Persists baselines to SQLite, updates adaptively via Exponential Moving Average (EMA),
computes percentage deviation (+292%), and flags anomalies when a metric exceeds
N standard deviations (default 3.0σ).
"""
import time
import math
import logging
import statistics
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
    deviation_pct: float               # Percentage difference from baseline (e.g. +145.2%)
    z_score: float
    is_anomaly: bool
    deviation_direction: str           # "HIGH", "LOW", "NORMAL"
    baseline_confidence: float = 1.0   # Maturity of the baseline (0.0 to 1.0)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AdaptiveBaselineLearner:
    def __init__(
        self,
        db: Optional[Database] = None,
        warmup_samples: int = 15,
        z_threshold: float = 3.0,
        alpha_ema: float = 0.05,     # Weight for exponential moving average updates
    ):
        self.db = db or get_db()
        self.warmup_samples = warmup_samples
        self.z_threshold = z_threshold
        self.alpha_ema = alpha_ema

        # In-memory sliding buffer for percentile and median calculations: (metric, target) -> List[float]
        self._history_buffer: Dict[Tuple[str, str], List[float]] = {}
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
        Updates running baseline for (metric_name, target) and returns MetricAnomaly
        with exact percentage deviation and adaptive EWMA.
        """
        key = (metric_name, target)
        now = time.time()

        if key not in self._history_buffer:
            self._history_buffer[key] = []
        buf = self._history_buffer[key]
        buf.append(value)
        if len(buf) > 100:
            buf.pop(0)

        # Baseline warm-up check
        if key not in self._cache:
            if len(buf) < self.warmup_samples:
                # Still in warm-up
                mean = statistics.mean(buf)
                stddev = statistics.stdev(buf) if len(buf) > 1 else 1.0
                confidence = round(len(buf) / self.warmup_samples, 2)
                diff = value - mean
                dev_pct = round((diff / max(abs(mean), 0.1)) * 100.0, 1)

                return MetricAnomaly(
                    metric_name=metric_name,
                    target=target,
                    current_value=round(value, 2),
                    baseline_mean=round(mean, 2),
                    baseline_stddev=round(stddev, 2),
                    deviation_pct=dev_pct,
                    z_score=0.0,
                    is_anomaly=False,
                    deviation_direction="NORMAL",
                    baseline_confidence=confidence,
                )
            else:
                # Completed warm-up: calculate initial baseline
                mean = statistics.mean(buf)
                stddev = statistics.stdev(buf) if len(buf) > 1 else 1.0
                sorted_vals = sorted(buf)
                median_val = statistics.median(sorted_vals)
                p95_idx = int(0.95 * len(sorted_vals))
                p95_val = sorted_vals[min(p95_idx, len(sorted_vals) - 1)]

                b = Baseline(
                    metric_name=metric_name,
                    target=target,
                    mean=round(mean, 2),
                    stddev=round(max(stddev, 0.5), 2),
                    median=round(median_val, 2),
                    p95=round(p95_val, 2),
                    min_val=round(min(buf), 2),
                    max_val=round(max(buf), 2),
                    sample_count=len(buf),
                    confidence_score=1.0,
                    last_updated=now,
                )
                self._cache[key] = b
                self.db.set_baseline(b)

        # Baseline exists: evaluate anomaly
        b = self._cache[key]
        std = max(b.stddev, 0.5)  # floor to avoid division by zero
        diff = value - b.mean
        z_score = diff / std
        dev_pct = round((diff / max(abs(b.mean), 0.1)) * 100.0, 1)

        is_anomaly = abs(z_score) >= self.z_threshold
        direction = "HIGH" if z_score > 0 else ("LOW" if z_score < 0 else "NORMAL")

        # Adaptively update baseline via Exponential Moving Average (EMA)
        effective_alpha = self.alpha_ema if not is_anomaly else (self.alpha_ema * 0.1)
        new_mean = (1 - effective_alpha) * b.mean + effective_alpha * value
        new_var = (1 - effective_alpha) * (b.stddev ** 2) + effective_alpha * ((value - new_mean) ** 2)
        new_stddev = max(math.sqrt(max(new_var, 0.01)), 0.5)

        sorted_buf = sorted(buf)
        b.mean = round(new_mean, 2)
        b.stddev = round(new_stddev, 2)
        b.median = round(statistics.median(sorted_buf), 2)
        p95_idx = int(0.95 * len(sorted_buf))
        b.p95 = round(sorted_buf[min(p95_idx, len(sorted_buf) - 1)], 2)
        b.min_val = round(min(buf), 2)
        b.max_val = round(max(buf), 2)
        b.sample_count += 1
        b.last_updated = now
        self.db.set_baseline(b)

        return MetricAnomaly(
            metric_name=metric_name,
            target=target,
            current_value=round(value, 2),
            baseline_mean=b.mean,
            baseline_stddev=b.stddev,
            deviation_pct=dev_pct,
            z_score=round(z_score, 2),
            is_anomaly=is_anomaly,
            deviation_direction=direction,
            baseline_confidence=1.0,
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

    def get_all_baseline_summaries(self) -> List[Dict[str, Any]]:
        """Returns all baselines formatted for UI display with deviation and confidence."""
        summaries = []
        for (m, t), b in self._cache.items():
            summaries.append({
                "metric_name": m,
                "target": t,
                "mean": b.mean,
                "stddev": b.stddev,
                "median": b.median,
                "p95": b.p95,
                "min": b.min_val,
                "max": b.max_val,
                "sample_count": b.sample_count,
                "confidence_score": b.confidence_score,
                "last_updated": b.last_updated,
            })
        return summaries

    def get_ui_summary(self) -> Dict[str, Any]:
        """Returns baseline metrics keyed by metric name for frontend presentation."""
        res = {}
        for (m, t), b in self._cache.items():
            res[m] = {
                "mean": b.mean,
                "stddev": b.stddev,
                "median": b.median,
                "p95": b.p95,
                "sample_count": b.sample_count,
                "confidence_score": b.confidence_score,
            }
        return res

