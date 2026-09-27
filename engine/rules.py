"""
Rule-Based Root-Cause Classifier (Expert System) for Network Autopsy.
Evaluates window features and metric anomalies against 8 core diagnostic rules:
1. Local gateway / Wi-Fi congestion
2. Fault at or beyond hop N (ISP / link segment)
3. DNS resolution issue
4. Target service down / port blocked / firewall rule
5. Network congestion / lossy link
6. Physical layer / cabling / interference issue
7. Route flap / path change
8. Application-layer failure at target service
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from engine.windowing import WindowFeatures
from engine.baseline import MetricAnomaly


@dataclass
class RuleDiagnosis:
    rule_name: str
    cause_label: str
    affected_layer: str            # Physical, Data-Link, Network, Transport, Application
    confidence_score: float        # 0.0 to 1.0
    evidence: Dict[str, Any]
    remediation_text: str
    fired: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RuleClassifier:
    def __init__(self):
        pass

    def evaluate(
        self,
        features: WindowFeatures,
        anomalies: Optional[List[MetricAnomaly]] = None,
        hop_eval: Optional[Dict[str, Any]] = None,
    ) -> List[RuleDiagnosis]:
        """Runs all expert rules against the current window features and anomalies."""
        diagnoses: List[RuleDiagnosis] = []
        anom_map = {a.metric_name: a for a in (anomalies or [])}

        # -------------------------------------------------------------
        # Rule 1: Local Gateway / Wi-Fi Congestion
        # Latency/loss spike isolated to hop 1 (gateway), normal or following beyond
        # -------------------------------------------------------------
        gw_loss_high = features.gateway_loss >= 15.0 or (features.hop1_loss >= 20.0)
        gw_lat_high = features.gateway_latency >= 60.0 or (features.hop1_rtt >= 60.0) or ("gateway_latency" in anom_map)
        if gw_loss_high or gw_lat_high:
            matched_evidence = {
                "gateway_latency_ms": features.gateway_latency,
                "gateway_loss_pct": features.gateway_loss,
                "hop1_rtt_ms": features.hop1_rtt,
                "hop1_loss_pct": features.hop1_loss,
            }
            # Confidence based on multiple corroborating signals
            conf = 0.65
            if gw_loss_high and gw_lat_high:
                conf += 0.20
            if features.jitter > 10.0:
                conf += 0.10

            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Local Gateway/Wi-Fi Congestion",
                    cause_label="Local gateway / Wi-Fi channel congestion or local router overload",
                    affected_layer="Data-Link / Network",
                    confidence_score=min(round(conf, 2), 0.95),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Inspect local Wi-Fi channel utilization and interference. "
                        "Switch Wi-Fi channel (2.4GHz to 5GHz/6GHz), restart local access point/router, "
                        "or test with a wired Ethernet cable."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 2: Fault at or Beyond Hop N (ISP / Link Segment)
        # Gateway is healthy, but external latency/loss spikes consistently at hop N
        # -------------------------------------------------------------
        gw_healthy = features.gateway_loss < 5.0 and features.gateway_latency < 30.0
        ext_degraded = features.external_loss >= 15.0 or features.external_latency >= 120.0 or ("external_latency" in anom_map)
        if gw_healthy and ext_degraded and features.hop_count >= 2:
            matched_evidence = {
                "gateway_loss_pct": features.gateway_loss,
                "gateway_latency_ms": features.gateway_latency,
                "external_latency_ms": features.external_latency,
                "external_loss_pct": features.external_loss,
                "hop_count": features.hop_count,
            }
            conf = 0.70
            if features.external_loss > 30.0:
                conf += 0.15
            if hop_eval and hop_eval.get("hop_confidence") in ("Medium", "High"):
                conf += 0.10

            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Fault at or Beyond Hop N",
                    cause_label="Upstream ISP routing degradation or intermediate carrier link failure",
                    affected_layer="Network",
                    confidence_score=min(round(conf, 2), 0.95),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Local network is healthy. Issue lies on upstream ISP or intermediate carrier. "
                        "Check ISP status page or traceroute hop breakdown for transit provider bottleneck."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 3: DNS Resolution Issue
        # DNS time far above baseline or failed, but direct-IP ping succeeds
        # -------------------------------------------------------------
        dns_slow_or_down = features.dns_loss_pct > 20.0 or features.dns_latency > 250.0 or ("dns_latency" in anom_map)
        ip_connectivity_good = features.external_loss < 20.0 and features.gateway_loss < 10.0
        if dns_slow_or_down and ip_connectivity_good:
            matched_evidence = {
                "dns_latency_ms": features.dns_latency,
                "dns_loss_pct": features.dns_loss_pct,
                "external_loss_pct": features.external_loss,
            }
            conf = 0.75
            if features.dns_loss_pct >= 50.0:
                conf += 0.20

            diagnoses.append(
                RuleDiagnosis(
                    rule_name="DNS Failure",
                    cause_label="DNS resolver timeout, misconfiguration, or upstream DNS server failure",
                    affected_layer="Application",
                    confidence_score=min(round(conf, 2), 0.98),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Configured DNS server is failing or responding slowly while direct IP routing works. "
                        "Switch DNS resolver to reliable public servers (1.1.1.1 or 8.8.8.8) or flush DNS cache."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 4: Target Service Down / Port Blocked / Firewall Rule
        # TCP connect probe times out or refused, while ICMP ping succeeds
        # -------------------------------------------------------------
        tcp_refused_or_timedout = features.tcp_connect_loss_pct >= 50.0
        icmp_succeeds = features.loss_pct < 20.0
        if tcp_refused_or_timedout and icmp_succeeds:
            matched_evidence = {
                "tcp_connect_loss_pct": features.tcp_connect_loss_pct,
                "tcp_connect_latency_ms": features.tcp_connect_latency,
                "icmp_loss_pct": features.loss_pct,
            }
            conf = 0.85
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Target Service Down / Firewall Block",
                    cause_label="Target service process inactive, port blocked by firewall, or ACL reject",
                    affected_layer="Transport",
                    confidence_score=round(conf, 2),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Host is reachable via ICMP (ping), but TCP port rejected or timed out connection. "
                        "Verify target daemon is actively running and check firewall / iptables rules."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 5: Network Congestion / Lossy Link
        # High retransmission rate + duplicate ACKs with moderate loss
        # -------------------------------------------------------------
        high_retrans = features.retrans_count >= 2 or features.retrans_rate >= 0.1 or ("retrans_rate" in anom_map)
        high_dup_acks = features.dup_ack_count >= 2 or features.dup_ack_rate >= 0.1
        if high_retrans or high_dup_acks:
            matched_evidence = {
                "retrans_count": features.retrans_count,
                "retrans_rate": features.retrans_rate,
                "dup_ack_count": features.dup_ack_count,
                "dup_ack_rate": features.dup_ack_rate,
                "packet_loss_pct": features.loss_pct,
            }
            conf = 0.70
            if high_retrans and high_dup_acks:
                conf += 0.20

            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Network Congestion / Lossy Link",
                    cause_label="Packet loss and out-of-order delivery inducing TCP fast-retransmits and throughput collapse",
                    affected_layer="Transport",
                    confidence_score=min(round(conf, 2), 0.95),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Multiple TCP retransmissions and duplicate ACKs detected. "
                        "Check for bufferbloat, excessive background downloads, or Wi-Fi packet drops."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 6: Physical Layer / Cabling / Interference Issue
        # Elevated checksum error rate on captured frames
        # -------------------------------------------------------------
        if features.checksum_errors >= 2 or features.checksum_error_rate >= 0.05 or ("checksum_error_rate" in anom_map):
            matched_evidence = {
                "checksum_errors": features.checksum_errors,
                "checksum_error_rate": features.checksum_error_rate,
            }
            conf = 0.85
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Physical Layer / Frame Corruption",
                    cause_label="Hardware, Ethernet cable degradation, or electromagnetic interference causing corrupted bit sequences",
                    affected_layer="Physical / Data-Link",
                    confidence_score=round(conf, 2),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Corrupted frame checksums detected at network interface. "
                        "Replace Ethernet cable, reseat patch connections, or check NIC driver/hardware health."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 7: Route Flap / Path Change
        # Hop count or sequence changed significantly between runs
        # -------------------------------------------------------------
        if features.route_changed:
            matched_evidence = {
                "route_changed": True,
                "hop_count": features.hop_count,
                "hop1_rtt_ms": features.hop1_rtt,
            }
            conf = 0.80
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Route Flap / Path Change",
                    cause_label="BGP or internal gateway routing instability causing path oscillation and transient packet drops",
                    affected_layer="Network",
                    confidence_score=round(conf, 2),
                    evidence=matched_evidence,
                    remediation_text=(
                        "Path topology changed dynamically between traceroute runs. "
                        "Check router dynamic routing protocol logs (OSPF/BGP) for flapping interface or failover event."
                    ),
                )
            )

        # -------------------------------------------------------------
        # Rule 8: Application-Layer Failure at Target Service
        # TCP handshake succeeds, but HTTP fails or returns 5xx/garbled response
        # -------------------------------------------------------------
        http_failed = (
            features.http_loss_pct >= 50.0
            or features.http_status_code >= 500
            or (features.http_ttfb >= 2500.0)
            or ("http_latency" in anom_map and features.http_latency > 2000.0)
        )
        tcp_ok = features.tcp_connect_loss_pct < 50.0
        if http_failed and tcp_ok:
            matched_evidence = {
                "http_status_code": features.http_status_code,
                "http_latency_ms": features.http_latency,
                "http_ttfb_ms": features.http_ttfb,
                "http_loss_pct": features.http_loss_pct,
            }
            conf = 0.85
            if features.http_status_code >= 500:
                conf += 0.10

            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Application Layer Failure",
                    cause_label="Application server crash, internal 5xx error, or HTTP worker exhaustion",
                    affected_layer="Application",
                    confidence_score=min(round(conf, 2), 0.98),
                    evidence=matched_evidence,
                    remediation_text=(
                        "TCP transport connection was successfully established, but the web application failed to respond "
                        "or returned HTTP 5xx. Inspect application logs, database connection pools, or worker processes."
                    ),
                )
            )

        return diagnoses
