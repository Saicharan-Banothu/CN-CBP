"""
Unit Tests for Network Autopsy Diagnosis Engine.
Tests:
1. Windowing feature aggregation correctness on synthetic data
2. Adaptive baseline learner anomaly detection and EMA updates
3. Rule-based expert classifier diagnostic rules firing
4. Hop confidence scoring (downgrades when traceroute-only, upgrades on multi-signal corroboration)
"""
import os
import sys
import time
import pytest

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import Database
from storage.models import ProbeResult, HopData, PacketEvent
from engine.windowing import WindowAggregator, WindowFeatures
from engine.baseline import AdaptiveBaselineLearner
from engine.rules import RuleClassifier
from engine.hop_confidence import HopConfidenceScorer


@pytest.fixture
def temp_db(tmp_path):
    """Provides a fresh isolated temporary SQLite database for testing."""
    db_file = tmp_path / "test_autopsy.db"
    return Database(str(db_file))


def test_windowing_aggregation(temp_db):
    """Verifies that WindowAggregator accurately computes rolling-window metrics."""
    now = time.time()

    # 1. Insert synthetic active probe results
    temp_db.insert_probe_result(
        ProbeResult(timestamp=now - 5, probe_type="ping", target="8.8.8.8", latency_ms=20.0, jitter_ms=2.0, loss_pct=0.0)
    )
    temp_db.insert_probe_result(
        ProbeResult(timestamp=now - 3, probe_type="ping", target="8.8.8.8", latency_ms=40.0, jitter_ms=4.0, loss_pct=10.0)
    )
    temp_db.insert_probe_result(
        ProbeResult(timestamp=now - 2, probe_type="dns", target="google.com", latency_ms=25.0, jitter_ms=0.0, loss_pct=0.0)
    )
    temp_db.insert_probe_result(
        ProbeResult(
            timestamp=now - 1, probe_type="http", target="http://127.0.0.1:8000/api/health",
            latency_ms=50.0, jitter_ms=0.0, loss_pct=0.0,
            extra_json='{"ttfb_ms": 20.0, "status_code": 200}'
        )
    )

    # 2. Insert synthetic passive capture events
    temp_db.insert_packet_event(
        PacketEvent(timestamp=now - 4, event_type="retransmission", src_ip="192.168.1.100", dst_ip="1.1.1.1", protocol="TCP")
    )
    temp_db.insert_packet_event(
        PacketEvent(timestamp=now - 2, event_type="dup_ack", src_ip="192.168.1.100", dst_ip="1.1.1.1", protocol="TCP")
    )

    aggregator = WindowAggregator(temp_db, window_seconds=20.0)
    features = aggregator.aggregate_current_window(end_ts=now)

    # Verify computations
    assert features.avg_latency == 30.0  # (20 + 40) / 2
    assert features.max_latency == 40.0
    assert features.jitter == 3.0       # (2 + 4) / 2
    assert features.loss_pct == 5.0      # (0 + 10) / 2
    assert features.dns_latency == 25.0
    assert features.http_latency == 50.0
    assert features.http_ttfb == 20.0
    assert features.http_status_code == 200
    assert features.retrans_count == 1
    assert features.dup_ack_count == 1
    assert features.raw_probe_count == 4
    assert features.raw_event_count == 2


def test_adaptive_baseline_learner(temp_db):
    """Verifies that the AdaptiveBaselineLearner learns baselines and flags standard deviation anomalies."""
    learner = AdaptiveBaselineLearner(temp_db, warmup_samples=10, z_threshold=3.0)

    # Warm-up phase with healthy 15ms latency (stddev ~1.0)
    for _ in range(10):
        anom = learner.update_and_check("avg_latency", "overall", 15.0)

    # After warm-up, baseline mean should be ~15.0
    baseline = temp_db.get_baseline("avg_latency", "overall")
    assert baseline is not None
    assert abs(baseline.mean - 15.0) < 0.5

    # Test normal variation: 16.0ms should NOT be anomalous
    normal_check = learner.update_and_check("avg_latency", "overall", 16.0)
    assert not normal_check.is_anomaly
    assert normal_check.z_score < 3.0

    # Test severe anomaly: 180.0ms should be flagged as anomaly
    spike_check = learner.update_and_check("avg_latency", "overall", 180.0)
    assert spike_check.is_anomaly
    assert spike_check.z_score > 3.0
    assert spike_check.deviation_direction == "HIGH"


def test_rule_engine_rules():
    """Verifies that expert system diagnostic rules fire accurately on matching telemetry."""
    classifier = RuleClassifier()

    # Case 1: Local Gateway Congestion Rule
    wf_gw = WindowFeatures(
        gateway_latency=120.0,
        gateway_loss=40.0,
        hop1_rtt=120.0,
        hop1_loss=40.0,
        jitter=20.0,
    )
    diagnoses_gw = classifier.evaluate(wf_gw)
    assert len(diagnoses_gw) > 0
    assert any("Gateway" in d.rule_name for d in diagnoses_gw)
    assert diagnoses_gw[0].affected_layer == "Data-Link / Network"
    assert diagnoses_gw[0].confidence_score >= 0.70

    # Case 2: DNS Failure Rule
    wf_dns = WindowFeatures(
        dns_latency=2500.0,
        dns_loss_pct=100.0,
        external_loss=0.0,   # IP routing works
        gateway_loss=0.0,
    )
    diagnoses_dns = classifier.evaluate(wf_dns)
    assert any("DNS" in d.rule_name for d in diagnoses_dns)
    assert any(d.affected_layer == "Application" for d in diagnoses_dns)

    # Case 3: Target Service Down / Firewall Block Rule
    wf_svc = WindowFeatures(
        tcp_connect_loss_pct=100.0,
        loss_pct=0.0,        # ICMP ping succeeds
    )
    diagnoses_svc = classifier.evaluate(wf_svc)
    assert any("Service Down" in d.rule_name for d in diagnoses_svc)
    assert any(d.affected_layer == "Transport" for d in diagnoses_svc)

    # Case 4: Physical CRC Corruption Rule
    wf_crc = WindowFeatures(
        checksum_errors=5,
        checksum_error_rate=0.25,
    )
    diagnoses_crc = classifier.evaluate(wf_crc)
    assert any("Physical Layer" in d.rule_name for d in diagnoses_crc)


def test_hop_confidence_scoring(temp_db):
    """
    Verifies that hop-level confidence scoring:
    - Never treats a single run as standalone proof
    - Caps confidence at Medium with regional unconfirmed label if only traceroute self-consistency exists
    - Upgrades confidence to High when multi-signal corroboration (direct probe + passive retransmissions) exists.
    """
    scorer = HopConfidenceScorer(temp_db, min_runs=3)

    # --- Scenario A: Single traceroute run only ---
    now = time.time()
    temp_db.insert_hop_data_batch([
        HopData(timestamp=now, traceroute_run_id="run_1", hop_number=1, ip="192.168.1.1", rtt_ms=2.0, loss_pct=0.0),
        HopData(timestamp=now, traceroute_run_id="run_1", hop_number=2, ip="10.0.0.1", rtt_ms=15.0, loss_pct=0.0),
        HopData(timestamp=now, traceroute_run_id="run_1", hop_number=3, ip="203.0.113.1", rtt_ms=180.0, loss_pct=50.0),
    ])

    res_single = scorer.evaluate_hops()
    assert res_single.hop_confidence == "Low"
    assert "insufficient runs" in res_single.hop_location.lower() or res_single.runs_analyzed < 2

    # --- Scenario B: 3 runs showing remote hop 4 degradation, but traceroute-only (no LAN corroboration) ---
    temp_db.clear_all_data()
    for i in range(3):
        ts = now + (i * 5)
        run_id = f"run_remote_{i}"
        temp_db.insert_hop_data_batch([
            HopData(timestamp=ts, traceroute_run_id=run_id, hop_number=1, ip="192.168.1.1", rtt_ms=2.0, loss_pct=0.0),
            HopData(timestamp=ts, traceroute_run_id=run_id, hop_number=2, ip="10.0.0.1", rtt_ms=8.0, loss_pct=0.0),
            HopData(timestamp=ts, traceroute_run_id=run_id, hop_number=3, ip="172.16.1.1", rtt_ms=12.0, loss_pct=0.0),
            HopData(timestamp=ts, traceroute_run_id=run_id, hop_number=4, ip="198.51.100.1", rtt_ms=190.0, loss_pct=60.0),
        ])

    res_remote = scorer.evaluate_hops(features=WindowFeatures(external_loss=0.0))
    # CRITICAL: Traceroute-only without external corroboration MUST be capped at Medium and regional
    assert res_remote.hop_confidence == "Medium"
    assert "likely region" in res_remote.hop_location
    assert "unconfirmed" in res_remote.hop_location

    # --- Scenario C: Hop 1 (Gateway) degradation corroborated by direct gateway probe and passive retransmissions ---
    temp_db.clear_all_data()
    for i in range(3):
        ts = now + (i * 5)
        run_id = f"run_gw_{i}"
        temp_db.insert_hop_data_batch([
            HopData(timestamp=ts, traceroute_run_id=run_id, hop_number=1, ip="192.168.1.1", rtt_ms=120.0, loss_pct=50.0),
            HopData(timestamp=ts, traceroute_run_id=run_id, hop_number=2, ip="10.0.0.1", rtt_ms=140.0, loss_pct=50.0),
        ])

    corroborated_features = WindowFeatures(
        gateway_latency=120.0,
        gateway_loss=50.0,
        retrans_count=5,
        dup_ack_count=3,
    )
    res_gw = scorer.evaluate_hops(features=corroborated_features)
    # Multi-signal corroboration upgrades to High
    assert res_gw.hop_confidence == "High"
    assert "Hop 1" in res_gw.hop_location
    assert res_gw.suspect_hop_num == 1
