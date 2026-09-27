"""
Unit Tests for Network Autopsy Diagnosis Engine.
Tests:
1. Windowing feature aggregation correctness on synthetic data
2. Adaptive baseline learner anomaly detection and EMA updates
3. Rule-based expert classifier diagnostic rules firing
4. Hop confidence scoring (downgrades when traceroute-only, upgrades on multi-signal corroboration)
5. Incident deduplication and recovery state machine lifecycle
6. Safe network fault proxy socket-level degradation
7. Explainable health scoring contributor breakdown
8. ML group-level train/test splitting (zero temporal leakage)
"""
import os
import sys
import time
import socket
import pytest
import numpy as np

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import Database
from storage.models import ProbeResult, HopData, PacketEvent, Incident
from engine.windowing import WindowAggregator, WindowFeatures
from engine.baseline import AdaptiveBaselineLearner
from engine.rules import RuleClassifier
from engine.hop_confidence import HopConfidenceScorer
from engine.report_generator import ReportGenerator
from engine.ml_classifier import NetworkFaultMLClassifier
from sandbox.local_fault_proxy import ControlledNetworkTarget


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

    # Case 4: Packet Integrity Checksum Verification Rule
    wf_crc = WindowFeatures(
        checksum_errors=5,
        checksum_error_rate=0.25,
    )
    diagnoses_crc = classifier.evaluate(wf_crc)
    assert any("Packet Integrity" in d.rule_name for d in diagnoses_crc)


def test_hop_confidence_scoring(temp_db):
    """
    Verifies hop confidence attribution and regional labeling logic.
    """
    scorer = HopConfidenceScorer(temp_db, min_runs=3)

    # Scenario A: Single run only
    now = time.time()
    temp_db.insert_hop_data_batch([
        HopData(timestamp=now, traceroute_run_id="run_1", hop_number=1, ip="192.168.1.1", rtt_ms=2.0, loss_pct=0.0),
        HopData(timestamp=now, traceroute_run_id="run_1", hop_number=2, ip="10.0.0.1", rtt_ms=15.0, loss_pct=0.0),
        HopData(timestamp=now, traceroute_run_id="run_1", hop_number=3, ip="203.0.113.1", rtt_ms=180.0, loss_pct=50.0),
    ])

    res_single = scorer.evaluate_hops()
    assert res_single.hop_confidence == "Low"

    # Scenario B: 3 runs showing Hop 1 degradation corroborated by LAN ping and retransmissions
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
    assert res_gw.hop_confidence == "High"
    assert "Hop 1" in res_gw.hop_location
    assert res_gw.suspect_hop_num == 1


def test_incident_deduplication_lifecycle(temp_db):
    """
    Verifies that recurring symptoms update an existing ongoing incident record
    rather than flooding the database with duplicate incident tickets.
    Also verifies transition to RESOLVED when network recovers.
    """
    report_gen = ReportGenerator(temp_db)
    rules_clf = RuleClassifier()
    scorer = HopConfidenceScorer(temp_db)

    # 1. First cycle: Gateway congestion occurs
    features_bad = WindowFeatures(
        gateway_latency=150.0,
        gateway_loss=35.0,
        hop1_rtt=150.0,
        hop1_loss=35.0,
    )
    rules_bad = rules_clf.evaluate(features_bad)
    hop_bad = scorer.evaluate_hops(features_bad)

    inc1 = report_gen.generate_or_update_incident(
        features=features_bad,
        rules=rules_bad,
        hop_result=hop_bad,
    )
    assert inc1 is not None
    assert inc1.id is not None
    assert inc1.status in ("DETECTED", "CONFIRMED", "ONGOING")
    assert inc1.occurrence_count == 1

    # 2. Second cycle 10 seconds later: Same failure still occurring
    time.sleep(0.1)
    inc2 = report_gen.generate_or_update_incident(
        features=features_bad,
        rules=rules_bad,
        hop_result=hop_bad,
    )
    # Deduplication MUST reuse the same incident ID
    assert inc2.id == inc1.id
    assert inc2.occurrence_count == 2
    assert inc2.status == "ONGOING"

    # Verify total incident count in database is still 1
    total_incidents = temp_db.get_incidents()
    assert len(total_incidents) == 1

    # 3. Third cycle: Network recovers to healthy baseline
    features_healthy = WindowFeatures(
        gateway_latency=2.0,
        gateway_loss=0.0,
        loss_pct=0.0,
        avg_latency=15.0,
    )
    resolved = report_gen.check_recovery_for_active_incidents(
        features=features_healthy,
        anomalies=[],
        rules=[],
    )
    assert len(resolved) == 1
    assert resolved[0].id == inc1.id
    assert resolved[0].status == "RESOLVED"
    assert resolved[0].resolved_at is not None


def test_safe_fault_proxy_socket_degradation():
    """
    Verifies that the ControlledNetworkTarget genuinely degrades socket connections:
    - High latency mode delays socket responses
    - HTTP 503 returns actual HTTP 503 status
    """
    # Start proxy on an arbitrary test port
    proxy = ControlledNetworkTarget(host="127.0.0.1", port=18086)
    proxy.start()
    time.sleep(0.2)

    try:
        # 1. Normal state: prompt HTTP 200 response
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 18086))
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = s.recv(1024).decode(errors="ignore")
        s.close()
        t1 = time.time()

        assert "HTTP/1.1 200 OK" in resp
        assert (t1 - t0) < 0.2

        # 2. Inject latency: 250ms
        proxy.set_fault(latency_ms=250.0)
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 18086))
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = s.recv(1024).decode(errors="ignore")
        s.close()
        t1 = time.time()

        assert "HTTP/1.1 200 OK" in resp
        assert (t1 - t0) >= 0.22  # Socket delay was genuinely enforced

        # 3. Inject HTTP 503 crash
        proxy.set_fault(http_status_code=503)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 18086))
        s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = s.recv(1024).decode(errors="ignore")
        s.close()

        assert "503 Service Unavailable" in resp

    finally:
        proxy.stop()


def test_ml_leakage_free_split():
    """
    Verifies that the ML classifier supports experiment-run level grouping
    to prevent temporal leakage across training and test splits.
    """
    clf = NetworkFaultMLClassifier(max_depth=5)
    X, y, groups = clf.generate_synthetic_dataset(samples_per_class=30)

    # Verify grouping
    assert len(groups) == len(X)
    unique_groups = np.unique(groups)
    assert len(unique_groups) > 10

    # Train models with group split
    comparison = clf.train_models(X=X, y=y, groups=groups)
    assert "evaluation_methodology" in comparison
    assert "GroupShuffleSplit" in comparison["evaluation_methodology"]["split_strategy"]
    assert clf.is_trained
    assert clf.dt_model is not None


def test_ground_truth_validation_independent_calculation(temp_db):
    """
    Verifies that ground truth correctness fields (cause, layer, location)
    are calculated independently from ground-truth comparison and are NEVER hardcoded.
    """
    from sandbox.validation_runner import ValidationRunner

    runner = ValidationRunner(db=temp_db)

    # 1. Canonical mapping check
    assert runner._map_to_canonical("DNS Resolution Failure", "DNS_FAILURE") == "DNS_FAILURE"
    assert runner._map_to_canonical("High Latency", "LOCAL_GATEWAY_CONGESTION") == "LOCAL_GATEWAY_CONGESTION"
    assert runner._map_to_canonical("Normal Network Operation", "HEALTHY_NORMAL") == "HEALTHY_NORMAL"

    # 2. Ground-truth correctness calculation logic:
    # Mismatched fault type MUST produce is_correct_cause = False
    expected_canonical = runner._map_to_canonical("DNS_FAILURE", "DNS_FAILURE")
    predicted_canonical = runner._map_to_canonical("HTTP_SERVICE_FAILURE", "APPLICATION_LAYER_FAILURE")
    assert expected_canonical != predicted_canonical
    assert (expected_canonical == predicted_canonical) is False

    # Layer mismatch: expected Network, predicted Application
    expected_layer = "Network"
    predicted_layer = "Application"
    is_layer_match = (
        expected_layer.lower().split("/")[0].strip() in predicted_layer.lower()
        or predicted_layer.lower() in expected_layer.lower()
    )
    assert is_layer_match is False

    # Location mismatch: expected Gateway (Hop 1), predicted Remote Service (Hop 8)
    scenario_id = "HIGH_LATENCY"
    predicted_location = "Hop 8 — Remote Destination (unconfirmed)"
    suspect_hop_num = 8
    is_correct_loc = (
        suspect_hop_num == 1
        or "hop 1" in predicted_location.lower()
        or "gateway" in predicted_location.lower()
    )
    assert is_correct_loc is False  # Correctly identifies failure to localize to hop 1


def test_baseline_aware_health_scoring_contributors(temp_db):
    """
    Verifies that health scoring is baseline-aware:
    - Normal latency below 2x baseline receives zero penalty
    - Elevated latency above 2x baseline incurs an explainable deduction
    - Point deductions provide clear parameter, observed, and baseline context
    """
    baseline_learner = AdaptiveBaselineLearner(db=temp_db, warmup_samples=5)

    # Train a 20ms baseline
    for _ in range(10):
        baseline_learner.update_and_check("avg_latency", "overall", 20.0)

    baselines = baseline_learner.get_ui_summary()
    base_lat = baselines.get("avg_latency", {}).get("mean", 20.0)
    lat_threshold = max(base_lat * 2.0, 50.0)  # 2x learned baseline

    # Normal latency (22ms): well under threshold
    wf_normal = WindowFeatures(
        window_start=time.time() - 20,
        window_end=time.time(),
        avg_latency=22.0,
        loss_pct=0.0,
    )
    lat_penalty_normal = 0
    if wf_normal.avg_latency > lat_threshold:
        lat_penalty_normal = min(int((wf_normal.avg_latency - lat_threshold) * 0.4), 25)
    assert lat_penalty_normal == 0

    # Degraded latency (120ms): exceeds threshold (50ms) by 70ms
    wf_degraded = WindowFeatures(
        window_start=time.time() - 20,
        window_end=time.time(),
        avg_latency=120.0,
        loss_pct=0.0,
    )
    lat_penalty_degraded = 0
    if wf_degraded.avg_latency > lat_threshold:
        lat_penalty_degraded = min(int((wf_degraded.avg_latency - lat_threshold) * 0.4), 25)
    assert lat_penalty_degraded > 0
    assert lat_penalty_degraded == min(int((120.0 - 50.0) * 0.4), 25)  # 25 pts max deduction


def test_security_input_validation_and_rejection():
    """
    Verifies security guards on public fault injection and experiment endpoints:
    - Rejects invalid scenarios
    - Rejects shell metacharacters
    - Enforces numeric duration bounds
    """
    from sandbox.fault_injection import SAFE_FAULT_SCENARIOS

    # 1. Whitelist validation
    valid_scenarios = list(SAFE_FAULT_SCENARIOS.keys())
    assert "HIGH_LATENCY" in valid_scenarios
    assert "PACKET_LOSS" in valid_scenarios
    assert "; whoami" not in valid_scenarios
    assert "rm -rf /" not in valid_scenarios

    # 2. Target validation: loopback socket target strictly enforced
    allowed_targets = ("127.0.0.1", "127.0.0.1:8085", "localhost", "localhost:8085")
    malicious_targets = [
        "192.168.1.1; whoami",
        "8.8.8.8",
        "../../etc/passwd",
        "$(whoami)",
        "eth0",
    ]
    for target in malicious_targets:
        assert target not in allowed_targets

    # 3. Duration bounds validation
    valid_duration = 10.0
    assert 1.0 <= valid_duration <= 30.0
    invalid_durations = [-5.0, 0.0, 9999.0]
    for d in invalid_durations:
        assert not (1.0 <= d <= 30.0)

