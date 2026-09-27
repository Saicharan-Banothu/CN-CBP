"""
Probe Scheduler for Network Autopsy.
Runs active probes at regular intervals, stores results in SQLite,
and provides on-demand single diagnostic run capability.
"""
import time
import json
import threading
import logging
from typing import List, Dict, Any, Optional

from storage.db import Database, get_db
from storage.models import ProbeResult, HopData
from agent.active_probes import (
    ping_probe,
    traceroute_probe,
    tcp_connect_probe,
    dns_resolve_probe,
    http_probe,
    _get_default_gateway_ip,
)

logger = logging.getLogger("network_autopsy.probe_scheduler")


class ProbeScheduler:
    def __init__(
        self,
        db: Optional[Database] = None,
        interval_seconds: float = 10.0,
        ping_targets: Optional[List[str]] = None,
        traceroute_targets: Optional[List[str]] = None,
        tcp_targets: Optional[List[Dict[str, Any]]] = None,
        dns_targets: Optional[List[Dict[str, str]]] = None,
        http_targets: Optional[List[str]] = None,
        passive_capture: Optional[Any] = None,
    ):
        self.db = db or get_db()
        self.interval = interval_seconds
        self.passive_capture = passive_capture
        gateway = _get_default_gateway_ip()

        self.ping_targets = ping_targets or [gateway, "8.8.8.8", "1.1.1.1"]
        self.traceroute_targets = traceroute_targets or ["8.8.8.8"]
        self.tcp_targets = tcp_targets or [
            {"target": gateway, "port": 80},
            {"target": "8.8.8.8", "port": 53},
            {"target": "127.0.0.1", "port": 8085},
            {"target": "127.0.0.1", "port": 8000},
        ]
        self.dns_targets = dns_targets or [
            {"hostname": "google.com", "dns_server": "8.8.8.8"},
            {"hostname": "cloudflare.com", "dns_server": "1.1.1.1"},
        ]
        self.http_targets = http_targets or [
            "http://127.0.0.1:8085/api/health",
            "http://127.0.0.1:8000/api/demo-service/health",
        ]

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def run_cycle_now(self) -> Dict[str, Any]:
        """Runs a complete diagnostic cycle across all configured active probes immediately."""
        cycle_start = time.time()
        results: Dict[str, Any] = {
            "pings": [],
            "traceroutes": [],
            "tcp_connects": [],
            "dns": [],
            "http": [],
            "cycle_duration_ms": 0.0,
        }

        # 1. Ping probes
        for target in self.ping_targets:
            try:
                res = ping_probe(target, count=3, timeout=1.0)
                probe_obj = ProbeResult(
                    timestamp=res["timestamp"],
                    probe_type="ping",
                    target=target,
                    latency_ms=res["latency_ms"],
                    jitter_ms=res["jitter_ms"],
                    loss_pct=res["loss_pct"],
                    extra_json=json.dumps(res.get("extra", {})),
                )
                self.db.insert_probe_result(probe_obj)
                results["pings"].append(res)
                if self.passive_capture:
                    self.passive_capture.record_observed_packets("ICMP", 6)
            except Exception as e:
                logger.error(f"Error running ping probe for {target}: {e}")

        # 2. Traceroute probes
        for target in self.traceroute_targets:
            try:
                tr_res = traceroute_probe(target, max_hops=12, timeout=1.0)
                probe_obj = ProbeResult(
                    timestamp=tr_res["timestamp"],
                    probe_type="traceroute",
                    target=target,
                    latency_ms=tr_res["latency_ms"],
                    jitter_ms=0.0,
                    loss_pct=tr_res["loss_pct"],
                    extra_json=json.dumps(tr_res.get("extra", {})),
                )
                self.db.insert_probe_result(probe_obj)

                # Store each hop
                hop_objs = [
                    HopData(
                        timestamp=tr_res["timestamp"],
                        traceroute_run_id=h["traceroute_run_id"],
                        hop_number=h["hop_number"],
                        ip=h["ip"],
                        rtt_ms=h["rtt_ms"],
                        loss_pct=h["loss_pct"],
                    )
                    for h in tr_res.get("hops", [])
                ]
                self.db.insert_hop_data_batch(hop_objs)
                results["traceroutes"].append(tr_res)
                if self.passive_capture:
                    self.passive_capture.record_observed_packets("ICMP", max(len(hop_objs) * 2, 4))
            except Exception as e:
                logger.error(f"Error running traceroute probe for {target}: {e}")

        # 3. TCP Connect probes
        for item in self.tcp_targets:
            target = item["target"]
            port = item["port"]
            try:
                tcp_res = tcp_connect_probe(target, port=port, timeout=1.5)
                probe_obj = ProbeResult(
                    timestamp=tcp_res["timestamp"],
                    probe_type="tcp_connect",
                    target=f"{target}:{port}",
                    latency_ms=tcp_res["latency_ms"],
                    jitter_ms=0.0,
                    loss_pct=tcp_res["loss_pct"],
                    extra_json=json.dumps(tcp_res.get("extra", {})),
                )
                self.db.insert_probe_result(probe_obj)
                results["tcp_connects"].append(tcp_res)
                if self.passive_capture:
                    self.passive_capture.record_observed_packets("TCP", 4)
            except Exception as e:
                logger.error(f"Error running TCP probe for {target}:{port}: {e}")

        # 4. DNS Probes
        for item in self.dns_targets:
            hostname = item["hostname"]
            dns_server = item["dns_server"]
            try:
                dns_res = dns_resolve_probe(hostname, dns_server=dns_server, timeout=1.5)
                probe_obj = ProbeResult(
                    timestamp=dns_res["timestamp"],
                    probe_type="dns",
                    target=hostname,
                    latency_ms=dns_res["latency_ms"],
                    jitter_ms=0.0,
                    loss_pct=dns_res["loss_pct"],
                    extra_json=json.dumps(dns_res.get("extra", {})),
                )
                self.db.insert_probe_result(probe_obj)
                results["dns"].append(dns_res)
                if self.passive_capture:
                    self.passive_capture.record_observed_packets("UDP", 2)
            except Exception as e:
                logger.error(f"Error running DNS probe for {hostname}: {e}")

        # 5. HTTP Probes
        for url in self.http_targets:
            try:
                http_res = http_probe(url, timeout=2.0)
                probe_obj = ProbeResult(
                    timestamp=http_res["timestamp"],
                    probe_type="http",
                    target=url,
                    latency_ms=http_res["latency_ms"],
                    jitter_ms=0.0,
                    loss_pct=http_res["loss_pct"],
                    extra_json=json.dumps(http_res.get("extra", {})),
                )
                self.db.insert_probe_result(probe_obj)
                results["http"].append(http_res)
                if self.passive_capture:
                    self.passive_capture.record_observed_packets("TCP", 6)
            except Exception as e:
                logger.error(f"Error running HTTP probe for {url}: {e}")

        results["cycle_duration_ms"] = round((time.time() - cycle_start) * 1000.0, 2)
        return results

    def _loop(self):
        logger.info(f"ProbeScheduler background thread started (interval={self.interval}s)")
        while self._running:
            try:
                self.run_cycle_now()
            except Exception as e:
                logger.error(f"Unexpected error in probe cycle: {e}")

            # Sleep in small slices so stopping is responsive
            sleep_slices = int(self.interval * 10)
            for _ in range(sleep_slices):
                if not self._running:
                    break
                time.sleep(0.1)

    def start(self):
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._loop, daemon=True, name="ProbeSchedulerThread")
                self._thread.start()

    def stop(self):
        with self._lock:
            self._running = False
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=3.0)

    def is_running(self) -> bool:
        return self._running
