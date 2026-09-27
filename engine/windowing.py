"""
Rolling-window feature aggregation for Network Autopsy.
Aggregates active probe results and passive packet capture events into
feature vectors across rolling time windows (default 20 seconds).
"""
import time
import json
import statistics
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from storage.db import Database, get_db
from storage.models import ProbeResult, HopData, PacketEvent
from agent.active_probes import _get_default_gateway_ip


@dataclass
class WindowFeatures:
    window_start: float = 0.0
    window_end: float = 0.0
    duration_s: float = 20.0

    # Active Probe Aggregates
    avg_latency: float = 0.0
    max_latency: float = 0.0
    jitter: float = 0.0
    loss_pct: float = 0.0

    gateway_latency: float = 0.0
    gateway_loss: float = 0.0
    external_latency: float = 0.0
    external_loss: float = 0.0

    dns_latency: float = 0.0
    dns_loss_pct: float = 0.0

    http_latency: float = 0.0
    http_ttfb: float = 0.0
    http_status_code: int = 200
    http_loss_pct: float = 0.0

    tcp_connect_latency: float = 0.0
    tcp_connect_loss_pct: float = 0.0

    # Passive Capture Aggregates
    retrans_count: int = 0
    dup_ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    checksum_errors: int = 0

    retrans_rate: float = 0.0        # events per second
    dup_ack_rate: float = 0.0        # events per second
    checksum_error_rate: float = 0.0 # events per second

    # Traceroute Aggregates
    hop_count: int = 0
    hop1_rtt: float = 0.0
    hop1_loss: float = 0.0
    hop2_rtt: float = 0.0
    hop2_loss: float = 0.0
    route_changed: bool = False

    raw_probe_count: int = 0
    raw_event_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_feature_vector(self) -> List[float]:
        """Returns standard ordered numeric feature list for ML classification."""
        return [
            float(self.avg_latency),
            float(self.max_latency),
            float(self.jitter),
            float(self.loss_pct),
            float(self.gateway_latency),
            float(self.gateway_loss),
            float(self.external_latency),
            float(self.external_loss),
            float(self.dns_latency),
            float(self.dns_loss_pct),
            float(self.http_latency),
            float(self.http_ttfb),
            float(self.http_status_code),
            float(self.http_loss_pct),
            float(self.tcp_connect_latency),
            float(self.tcp_connect_loss_pct),
            float(self.retrans_count),
            float(self.dup_ack_count),
            float(self.checksum_errors),
            float(self.retrans_rate),
            float(self.dup_ack_rate),
            float(self.checksum_error_rate),
            float(self.hop_count),
            float(self.hop1_rtt),
            float(self.hop1_loss),
            1.0 if self.route_changed else 0.0,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "avg_latency",
            "max_latency",
            "jitter",
            "loss_pct",
            "gateway_latency",
            "gateway_loss",
            "external_latency",
            "external_loss",
            "dns_latency",
            "dns_loss_pct",
            "http_latency",
            "http_ttfb",
            "http_status_code",
            "http_loss_pct",
            "tcp_connect_latency",
            "tcp_connect_loss_pct",
            "retrans_count",
            "dup_ack_count",
            "checksum_errors",
            "retrans_rate",
            "dup_ack_rate",
            "checksum_error_rate",
            "hop_count",
            "hop1_rtt",
            "hop1_loss",
            "route_changed",
        ]


class WindowAggregator:
    def __init__(self, db: Optional[Database] = None, window_seconds: float = 20.0):
        self.db = db or get_db()
        self.window_seconds = window_seconds
        self.gateway_ip = _get_default_gateway_ip()
        self._last_traceroute_hop_ips: List[str] = []

    def aggregate_current_window(self, end_ts: Optional[float] = None) -> WindowFeatures:
        """Collects metrics in [end_ts - window_seconds, end_ts] and computes aggregate features."""
        now = end_ts or time.time()
        start_ts = now - self.window_seconds

        probes = self.db.get_recent_probe_results(since_ts=start_ts)
        events = self.db.get_recent_packet_events(since_ts=start_ts)

        feat = WindowFeatures(
            window_start=start_ts,
            window_end=now,
            duration_s=self.window_seconds,
            raw_probe_count=len(probes),
            raw_event_count=len(events),
        )

        # 1. Process Active Probes
        ping_latencies: List[float] = []
        ping_jitters: List[float] = []
        ping_losses: List[float] = []

        gw_lats: List[float] = []
        gw_losses: List[float] = []
        ext_lats: List[float] = []
        ext_losses: List[float] = []

        dns_lats: List[float] = []
        dns_losses: List[float] = []

        http_lats: List[float] = []
        http_ttfbs: List[float] = []
        http_statuses: List[int] = []
        http_losses: List[float] = []

        tcp_lats: List[float] = []
        tcp_losses: List[float] = []

        for p in probes:
            if p.probe_type == "ping":
                ping_latencies.append(p.latency_ms)
                ping_jitters.append(p.jitter_ms)
                ping_losses.append(p.loss_pct)

                if self.gateway_ip in p.target:
                    gw_lats.append(p.latency_ms)
                    gw_losses.append(p.loss_pct)
                else:
                    ext_lats.append(p.latency_ms)
                    ext_losses.append(p.loss_pct)

            elif p.probe_type == "dns":
                dns_lats.append(p.latency_ms)
                dns_losses.append(p.loss_pct)

            elif p.probe_type == "http":
                http_lats.append(p.latency_ms)
                http_losses.append(p.loss_pct)
                extra = p.get_extra()
                if "ttfb_ms" in extra:
                    http_ttfbs.append(float(extra["ttfb_ms"]))
                if "status_code" in extra and extra["status_code"] > 0:
                    http_statuses.append(int(extra["status_code"]))

            elif p.probe_type == "tcp_connect":
                tcp_lats.append(p.latency_ms)
                tcp_losses.append(p.loss_pct)

        # Compute averages for active probes
        if ping_latencies:
            feat.avg_latency = round(statistics.mean(ping_latencies), 2)
            feat.max_latency = round(max(ping_latencies), 2)
        if ping_jitters:
            feat.jitter = round(statistics.mean(ping_jitters), 2)
        if ping_losses:
            feat.loss_pct = round(statistics.mean(ping_losses), 2)

        if gw_lats:
            feat.gateway_latency = round(statistics.mean(gw_lats), 2)
        if gw_losses:
            feat.gateway_loss = round(statistics.mean(gw_losses), 2)

        if ext_lats:
            feat.external_latency = round(statistics.mean(ext_lats), 2)
        if ext_losses:
            feat.external_loss = round(statistics.mean(ext_losses), 2)

        if dns_lats:
            feat.dns_latency = round(statistics.mean(dns_lats), 2)
        if dns_losses:
            feat.dns_loss_pct = round(statistics.mean(dns_losses), 2)

        if http_lats:
            feat.http_latency = round(statistics.mean(http_lats), 2)
        if http_ttfbs:
            feat.http_ttfb = round(statistics.mean(http_ttfbs), 2)
        if http_statuses:
            feat.http_status_code = http_statuses[-1]
        if http_losses:
            feat.http_loss_pct = round(statistics.mean(http_losses), 2)

        if tcp_lats:
            feat.tcp_connect_latency = round(statistics.mean(tcp_lats), 2)
        if tcp_losses:
            feat.tcp_connect_loss_pct = round(statistics.mean(tcp_losses), 2)

        # 2. Process Passive Events
        retrans = 0
        dup_acks = 0
        rsts = 0
        fins = 0
        chk_errs = 0

        for e in events:
            if e.event_type == "retransmission":
                retrans += 1
            elif e.event_type == "dup_ack":
                dup_acks += 1
            elif e.event_type == "rst":
                rsts += 1
            elif e.event_type == "fin":
                fins += 1
            elif e.event_type == "checksum_error":
                chk_errs += 1

        feat.retrans_count = retrans
        feat.dup_ack_count = dup_acks
        feat.rst_count = rsts
        feat.fin_count = fins
        feat.checksum_errors = chk_errs

        duration = max(self.window_seconds, 1.0)
        feat.retrans_rate = round(retrans / duration, 3)
        feat.dup_ack_rate = round(dup_acks / duration, 3)
        feat.checksum_error_rate = round(chk_errs / duration, 3)

        # 3. Process Latest Traceroute Data
        recent_runs = self.db.get_latest_traceroute_runs(num_runs=2)
        if recent_runs:
            latest_run_id, _, hops = recent_runs[0]
            feat.hop_count = len(hops)
            for h in hops:
                if h.hop_number == 1:
                    feat.hop1_rtt = h.rtt_ms
                    feat.hop1_loss = h.loss_pct
                elif h.hop_number == 2:
                    feat.hop2_rtt = h.rtt_ms
                    feat.hop2_loss = h.loss_pct

            # Check for route flap (compare with previous run)
            current_ips = [h.ip for h in hops if h.ip != "*"]
            if len(recent_runs) >= 2:
                _, _, prev_hops = recent_runs[1]
                prev_ips = [h.ip for h in prev_hops if h.ip != "*"]
                if len(prev_ips) > 0 and len(current_ips) > 0:
                    # If hop count differs by > 1 or 2+ hop IPs changed
                    if abs(len(current_ips) - len(prev_ips)) >= 2:
                        feat.route_changed = True
                    elif current_ips[:min(len(current_ips), len(prev_ips))] != prev_ips[:min(len(current_ips), len(prev_ips))]:
                        feat.route_changed = True

        return feat
