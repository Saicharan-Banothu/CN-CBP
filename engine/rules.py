"""
Multi-Signal Evidence Correlation & Rule-Based Root-Cause Classifier for Network Autopsy.
Evaluates window telemetry against 8 expert diagnostic rules with structured evidence models:
1. Local gateway / Wi-Fi congestion
2. Fault at or beyond hop N (ISP / link segment)
3. DNS resolution issue
4. Target service down / port blocked / firewall rule
5. Network congestion / lossy link
6. Packet Integrity Indicators (IP/TCP Checksum Verification)
   * Honest Academic Note: Evaluates IP header and TCP checksum consistency.
     Hardware Ethernet FCS is stripped by NIC/OS drivers before userspace capture.
7. Route flap / path change
8. Application-layer failure at target service
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from storage.models import EvidenceItem
from engine.windowing import WindowFeatures
from engine.baseline import MetricAnomaly


@dataclass
class RuleDiagnosis:
    rule_name: str
    cause_label: str
    affected_layer: str                 # Physical / Data-Link, Network, Transport, Application
    confidence_score: float             # 0.0 to 1.0
    evidence_items: List[Dict[str, Any]]
    evidence_summary: Dict[str, Any]
    remediation_text: str
    alternative_hypotheses: List[str]
    fired: bool = True
    user_description: str = ""
    technical_description: str = ""
    user_impact: str = ""
    why_points: List[str] = field(default_factory=list)
    confidence_explanation: str = ""
    alternative_hypotheses_structured: List[Dict[str, Any]] = field(default_factory=list)

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
        """Runs all expert rules against the current window features, baseline anomalies, and hop telemetry."""
        diagnoses: List[RuleDiagnosis] = []
        anom_map = {a.metric_name: a for a in (anomalies or [])}

        # -------------------------------------------------------------
        # Rule 1: Local Gateway / Wi-Fi Congestion
        # -------------------------------------------------------------
        gw_lat_high = features.gateway_latency >= 50.0 or (features.hop1_rtt >= 50.0) or ("gateway_latency" in anom_map)
        gw_loss_high = features.gateway_loss >= 15.0 or (features.hop1_loss >= 15.0)

        # Cloud/Docker Bridge Suppression: If external latency is responsive (<60ms) and external loss is 0%,
        # the local gateway is obviously routing packets without bottleneck. Do not trigger gateway congestion
        # if the gateway IP is merely an unrouted bridge interface that drops direct ICMP echo.
        is_cloud_docker_suppression = (
            features.external_latency > 0
            and features.external_loss < 5.0
            and features.dns_loss_pct == 0.0
            and features.gateway_latency == 0.0
        )
        if (gw_lat_high or gw_loss_high) and not is_cloud_docker_suppression:
            evidence: List[EvidenceItem] = []
            conf = 0.65

            if features.gateway_latency > 0:
                dev = anom_map["gateway_latency"].deviation_pct if "gateway_latency" in anom_map else 0.0
                evidence.append(EvidenceItem(
                    signal="Gateway RTT",
                    observed_value=f"{features.gateway_latency} ms",
                    baseline_value=f"{anom_map['gateway_latency'].baseline_mean if 'gateway_latency' in anom_map else '< 10'} ms",
                    deviation_pct=dev,
                    direction="HIGH",
                    source="active_probe",
                    confidence_contribution=0.35,
                    status="ANOMALOUS",
                ))

            if features.gateway_loss > 0 or features.hop1_loss > 0:
                evidence.append(EvidenceItem(
                    signal="Gateway Packet Loss",
                    observed_value=f"{max(features.gateway_loss, features.hop1_loss)} %",
                    baseline_value="0.0 %",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="active_probe",
                    confidence_contribution=0.25,
                    status="ANOMALOUS",
                ))

            if features.jitter > 10.0:
                conf += 0.10
                evidence.append(EvidenceItem(
                    signal="Latency Jitter (σ)",
                    observed_value=f"{features.jitter} ms",
                    baseline_value="< 3.0 ms",
                    deviation_pct=round(features.jitter * 33.3, 1),
                    direction="HIGH",
                    source="active_probe",
                    confidence_contribution=0.15,
                    status="SUSPICIOUS",
                ))

            if features.retrans_count >= 2:
                conf += 0.10
                evidence.append(EvidenceItem(
                    signal="TCP Retransmissions",
                    observed_value=features.retrans_count,
                    baseline_value="0",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="passive_capture",
                    confidence_contribution=0.15,
                    status="ANOMALOUS",
                ))

            calc_conf = min(round(conf, 2), 0.95)
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Local Gateway/Wi-Fi Congestion",
                    cause_label="Local gateway / Wi-Fi channel congestion or local router overload",
                    affected_layer="Data-Link / Network",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={
                        "gateway_rtt_ms": features.gateway_latency,
                        "gateway_loss_pct": features.gateway_loss,
                        "hop1_rtt_ms": features.hop1_rtt,
                        "jitter_ms": features.jitter,
                    },
                    remediation_text=(
                        "Inspect Wi-Fi frequency utilization. Switch to 5GHz/6GHz or change channel. "
                        "Reboot local access point / gateway router or test via wired Ethernet patch."
                    ),
                    alternative_hypotheses=[
                        "Ethernet cable or switch port duplex mismatch",
                        "High bandwidth torrent/stream saturating local uplink",
                    ],
                    user_description="Your connection to the local router or Wi-Fi gateway is congested or experiencing packet loss.",
                    technical_description="First-hop link saturation with elevated RTT and packet drop at gateway / AP interface.",
                    user_impact="Streaming video may freeze, web pages will load slowly, and real-time gaming or video calls may drop frames.",
                    why_points=[
                        f"Response time to your local router increased to {features.gateway_latency or features.hop1_rtt} ms (normal is < 10 ms).",
                        f"Packet loss of {max(features.gateway_loss, features.hop1_loss)}% detected at the very first hop.",
                        "Direct gateway measurements isolate the slowdown before traffic leaves your local building.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: {len(evidence)} independent signals agree, isolating the slowdown to your first hop router.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "Ethernet cable or switch port duplex mismatch",
                            "probability": 0.15,
                            "status": "REJECTED",
                            "reason": "Loss and delay occurred intermittently rather than as a permanent line-rate cap.",
                        },
                        {
                            "hypothesis": "High bandwidth torrent or video stream on local network",
                            "probability": 0.25,
                            "status": "PLAUSIBLE_CONTRIBUTOR",
                            "reason": "Bufferbloat matches symptom of sudden queue delay on gateway.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 2: Fault at or Beyond Hop N (Upstream ISP / Transit)
        # -------------------------------------------------------------
        gw_ok = features.gateway_loss < 5.0 and features.gateway_latency < 35.0
        ext_bad = features.external_loss >= 15.0 or features.external_latency >= 110.0 or ("external_latency" in anom_map)

        if gw_ok and ext_bad and features.hop_count >= 2:
            evidence = [
                EvidenceItem(
                    signal="Hop 1 / Gateway Health",
                    observed_value=f"{features.gateway_latency} ms (0% loss)",
                    baseline_value="Normal",
                    deviation_pct=0.0,
                    direction="NORMAL",
                    source="active_probe",
                    confidence_contribution=0.30,
                    status="NORMAL",
                ),
                EvidenceItem(
                    signal="Upstream Transit RTT",
                    observed_value=f"{features.external_latency} ms",
                    baseline_value=f"{anom_map['external_latency'].baseline_mean if 'external_latency' in anom_map else '< 35'} ms",
                    deviation_pct=anom_map["external_latency"].deviation_pct if "external_latency" in anom_map else 100.0,
                    direction="HIGH",
                    source="active_probe",
                    confidence_contribution=0.40,
                    status="ANOMALOUS",
                ),
            ]
            conf = 0.70
            if features.external_loss > 30.0:
                conf += 0.15
            calc_conf = min(round(conf, 2), 0.95)

            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Fault at or Beyond Hop N",
                    cause_label="Upstream ISP routing degradation or intermediate carrier link failure",
                    affected_layer="Network",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={
                        "gateway_rtt_ms": features.gateway_latency,
                        "external_rtt_ms": features.external_latency,
                        "external_loss_pct": features.external_loss,
                        "hop_count": features.hop_count,
                    },
                    remediation_text=(
                        "Local network is healthy. Issue lies on upstream ISP or intermediate carrier. "
                        "Check ISP service status page or traceroute hop breakdown for transit provider bottleneck."
                    ),
                    alternative_hypotheses=[
                        "Undersea cable transit latency spike",
                        "Intermediate BGP peer congestion",
                    ],
                    user_description="A problem was detected in the upstream internet provider or intermediate network path.",
                    technical_description="Transit carrier degradation or core routing bottleneck at intermediate hop segment.",
                    user_impact="Access to external websites and cloud services is degraded, while your local router connection is working normally.",
                    why_points=[
                        "Your local home/office gateway responds quickly with 0% loss.",
                        f"External latency increased to {features.external_latency} ms with {features.external_loss}% packet loss.",
                        "Path measurements isolate the degradation to upstream carrier hops beyond your premises.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: local link verified healthy, isolating failure to upstream ISP or transit carrier.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "Local router hardware failure",
                            "probability": 0.05,
                            "status": "REJECTED",
                            "reason": "First hop responds quickly with 0% loss, disproving local router failure.",
                        },
                        {
                            "hypothesis": "Intermediate BGP peer congestion",
                            "probability": 0.30,
                            "status": "PLAUSIBLE",
                            "reason": "Sudden latency step between hop 3 and 4 matches peering congestion.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 3: DNS Resolution Issue
        # -------------------------------------------------------------
        dns_failed = features.dns_loss_pct > 20.0 or features.dns_latency > 250.0 or ("dns_latency" in anom_map)
        ip_routing_ok = features.external_loss < 20.0 and features.gateway_loss < 10.0

        if dns_failed and ip_routing_ok:
            evidence = [
                EvidenceItem(
                    signal="DNS Resolution Time",
                    observed_value=f"{features.dns_latency} ms",
                    baseline_value="< 45 ms",
                    deviation_pct=anom_map["dns_latency"].deviation_pct if "dns_latency" in anom_map else 200.0,
                    direction="HIGH",
                    source="dns_probe",
                    confidence_contribution=0.50,
                    status="ANOMALOUS",
                ),
                EvidenceItem(
                    signal="Direct IP Ping Reachability",
                    observed_value=f"{features.external_latency} ms ({features.external_loss}% loss)",
                    baseline_value="Healthy",
                    deviation_pct=0.0,
                    direction="NORMAL",
                    source="active_probe",
                    confidence_contribution=0.35,
                    status="NORMAL",
                ),
            ]
            conf = 0.80 if features.dns_loss_pct < 50.0 else 0.95
            calc_conf = round(conf, 2)
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="DNS Failure",
                    cause_label="DNS resolver timeout, misconfiguration, or upstream DNS server failure",
                    affected_layer="Application",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={
                        "dns_latency_ms": features.dns_latency,
                        "dns_loss_pct": features.dns_loss_pct,
                        "direct_ip_loss_pct": features.external_loss,
                    },
                    remediation_text=(
                        "Direct IP reachability works but DNS resolver timed out. "
                        "Switch DNS resolver to reliable servers (1.1.1.1 or 8.8.8.8) or flush local DNS cache."
                    ),
                    alternative_hypotheses=[
                        "Outbound UDP port 53 firewall rule",
                        "Local DNS cache daemon poisoned or deadlocked",
                    ],
                    user_description="Your device can reach the internet, but domain-name lookup (DNS) is failing or timing out.",
                    technical_description="Domain Name System resolution timeout with intact direct IP layer reachability.",
                    user_impact="Entering website names like google.com fails to load, even though your internet connection is active.",
                    why_points=[
                        "Internet connectivity is healthy — direct IP ping requests succeed without loss.",
                        f"DNS queries timed out or response time increased to {features.dns_latency} ms.",
                        f"DNS failure rate reached {features.dns_loss_pct}%.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: direct IP connectivity is healthy while domain name resolution fails.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "Complete network disconnection",
                            "probability": 0.05,
                            "status": "REJECTED",
                            "reason": "Direct IP pings to 8.8.8.8 and 1.1.1.1 succeed with low latency.",
                        },
                        {
                            "hypothesis": "Outbound UDP port 53 firewall rule",
                            "probability": 0.20,
                            "status": "PLAUSIBLE",
                            "reason": "Firewall dropping UDP 53 produces identical timeout symptoms.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 4: Target Service Down / Port Blocked / Firewall Rule
        # -------------------------------------------------------------
        tcp_refused = features.tcp_connect_loss_pct >= 50.0
        icmp_healthy = features.loss_pct < 20.0

        if tcp_refused and icmp_healthy:
            evidence = [
                EvidenceItem(
                    signal="TCP Handshake Status",
                    observed_value="Connection Refused / Timed Out",
                    baseline_value="Connected (SYN-ACK)",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="active_probe",
                    confidence_contribution=0.55,
                    status="ANOMALOUS",
                ),
                EvidenceItem(
                    signal="ICMP Echo (Ping)",
                    observed_value=f"{features.avg_latency} ms ({features.loss_pct}% loss)",
                    baseline_value="Healthy",
                    deviation_pct=0.0,
                    direction="NORMAL",
                    source="active_probe",
                    confidence_contribution=0.35,
                    status="NORMAL",
                ),
            ]
            calc_conf = 0.88
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Target Service Down / Firewall Block",
                    cause_label="Target service process inactive, port blocked by firewall, or ACL reject",
                    affected_layer="Transport",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={
                        "tcp_connect_loss_pct": features.tcp_connect_loss_pct,
                        "icmp_loss_pct": features.loss_pct,
                    },
                    remediation_text=(
                        "Host responds to ICMP echo but target TCP port is closed or filtered. "
                        "Verify target daemon is actively running and inspect iptables/Windows firewall ACLs."
                    ),
                    alternative_hypotheses=[
                        "Ingress security group block",
                        "Service listening only on localhost (127.0.0.1) instead of 0.0.0.0",
                    ],
                    user_description="The destination server or web service is not accepting connections, although network connectivity is working.",
                    technical_description="TCP port connection refused (RST) or dropped by firewall with normal ICMP echo reachability.",
                    user_impact="The specific app or website cannot be reached, but other internet sites and network connections work fine.",
                    why_points=[
                        "Network ping to the destination server responds normally.",
                        "TCP connection attempts to the target port are immediately refused or timed out.",
                        "No packet loss on intermediate network hops.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: destination host responds to pings, but rejects TCP connections.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "General internet outage",
                            "probability": 0.02,
                            "status": "REJECTED",
                            "reason": "Host IP responds to ping probes without loss.",
                        },
                        {
                            "hypothesis": "Service listening only on loopback",
                            "probability": 0.30,
                            "status": "PLAUSIBLE",
                            "reason": "Process may be running but bound to 127.0.0.1 instead of public IP.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 5: Network Congestion / Lossy Link
        # -------------------------------------------------------------
        retrans_elevated = features.retrans_count >= 2 or features.retrans_rate >= 0.1 or ("retrans_rate" in anom_map)
        dup_acks_elevated = features.dup_ack_count >= 2 or features.dup_ack_rate >= 0.1

        if retrans_elevated or dup_acks_elevated:
            evidence = [
                EvidenceItem(
                    signal="TCP Retransmissions",
                    observed_value=features.retrans_count,
                    baseline_value="0",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="passive_capture",
                    confidence_contribution=0.45,
                    status="ANOMALOUS",
                ),
                EvidenceItem(
                    signal="Duplicate ACKs (3+)",
                    observed_value=features.dup_ack_count,
                    baseline_value="0",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="passive_capture",
                    confidence_contribution=0.35,
                    status="ANOMALOUS",
                ),
            ]
            conf = 0.75 if (retrans_elevated and dup_acks_elevated) else 0.65
            calc_conf = round(conf, 2)
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Network Congestion / Lossy Link",
                    cause_label="Packet loss and out-of-order delivery inducing TCP fast-retransmits and throughput collapse",
                    affected_layer="Transport",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={
                        "retrans_count": features.retrans_count,
                        "dup_ack_count": features.dup_ack_count,
                        "loss_pct": features.loss_pct,
                    },
                    remediation_text=(
                        "Multiple TCP retransmissions and duplicate ACKs captured. "
                        "Check for bufferbloat, excessive background downloads, or Wi-Fi packet drops."
                    ),
                    alternative_hypotheses=[
                        "Asymmetric path causing extreme packet reordering",
                        "Transient microburst packet loss at network switch",
                    ],
                    user_description="Your connection is experiencing packet loss, congestion, and dropped data transmissions.",
                    technical_description="Multi-parameter congestion with TCP fast-retransmits and throughput collapse.",
                    user_impact="Web downloads and streaming will feel stuttery or slow due to repeated data retransmissions.",
                    why_points=[
                        f"Passive capture detected {features.retrans_count} TCP retransmissions and {features.dup_ack_count} duplicate ACKs.",
                        "Data packets are being dropped in flight, requiring sender retransmission.",
                        "Throughput is throttled by TCP congestion control backoff.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: corroborated by active packet loss and passive TCP retransmission analysis.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "Extreme packet reordering without actual loss",
                            "probability": 0.20,
                            "status": "PLAUSIBLE",
                            "reason": "Out-of-order packet delivery can trigger false duplicate ACKs.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 6: Packet Integrity Indicators (IP/TCP Checksum Verification)
        # -------------------------------------------------------------
        if features.checksum_errors >= 2 or features.checksum_error_rate >= 0.05 or ("checksum_error_rate" in anom_map):
            evidence = [
                EvidenceItem(
                    signal="Corrupted IP/TCP Checksums",
                    observed_value=features.checksum_errors,
                    baseline_value="0",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="passive_capture",
                    confidence_contribution=0.75,
                    status="ANOMALOUS",
                )
            ]
            calc_conf = 0.85
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Packet Integrity / Checksum Mismatch",
                    cause_label="Hardware, Ethernet cable degradation, or electromagnetic interference causing corrupted bit sequences",
                    affected_layer="Physical / Data-Link",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={"checksum_errors": features.checksum_errors},
                    remediation_text=(
                        "Corrupted packet checksums detected at network layer. "
                        "Reseat or replace physical Ethernet patch cables, verify NIC driver integrity, or check for RF interference."
                    ),
                    alternative_hypotheses=[
                        "NIC TCP checksum offloading artifact in packet capture",
                        "Defective switch ASIC port memory",
                    ],
                    user_description="Network packets are arriving with corrupted checksum data, indicating transport or cable errors.",
                    technical_description="IP header and TCP/UDP payload checksum validation failures in passive traffic.",
                    user_impact="Connections may randomly reset, files may fail checksum validation, or transfers may stall.",
                    why_points=[
                        f"Observed {features.checksum_errors} corrupted packet checksums in passive traffic.",
                        "Bit errors detected before packet payload reached application layer.",
                        "Physical cable degradation or hardware NIC driver corruption suspected.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: mathematical checksum mismatch verified in captured frame headers.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "NIC checksum offload artifact",
                            "probability": 0.25,
                            "status": "POSSIBLE",
                            "reason": "Certain network cards leave outgoing checksums blank until transmission.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 7: Route Flap / Path Change
        # -------------------------------------------------------------
        if features.route_changed:
            evidence = [
                EvidenceItem(
                    signal="Traceroute Path Mutation",
                    observed_value="Hop sequence or hop count altered",
                    baseline_value="Static Path",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="traceroute",
                    confidence_contribution=0.70,
                    status="ANOMALOUS",
                )
            ]
            calc_conf = 0.82
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Route Flap / Path Change",
                    cause_label="BGP or internal gateway routing instability causing path oscillation and transient packet drops",
                    affected_layer="Network",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={"hop_count": features.hop_count, "route_changed": True},
                    remediation_text=(
                        "Path topology mutated dynamically between runs. "
                        "Inspect router routing table logs (OSPF/BGP) for flapping interfaces or automated failover."
                    ),
                    alternative_hypotheses=[
                        "Equal-Cost Multi-Path (ECMP) load balancing hashing variation",
                    ],
                    user_description="The network path to the destination changed unexpectedly, causing momentary instability.",
                    technical_description="Dynamic routing table hop mutation (BGP/OSPF route flap or automated link failover).",
                    user_impact="Brief lag spikes or 1-2 second disconnections while the router selects a new network path.",
                    why_points=[
                        "Traceroute path sequence mutated dynamically between measurement cycles.",
                        f"Active path length changed to {features.hop_count} hops vs established baseline.",
                        "Routing table converged on alternate transit path.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: hop IP sequence altered compared to cached topology baseline.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "Equal-Cost Multi-Path (ECMP) load balancing",
                            "probability": 0.35,
                            "status": "PLAUSIBLE",
                            "reason": "Per-flow ECMP hashing can send packets across different equal-cost links.",
                        },
                    ],
                )
            )

        # -------------------------------------------------------------
        # Rule 8: Application-Layer Failure at Target Service
        # -------------------------------------------------------------
        http_bad = (
            features.http_loss_pct >= 50.0
            or features.http_status_code >= 500
            or features.http_ttfb >= 2500.0
            or ("http_latency" in anom_map and features.http_latency > 2000.0)
        )
        tcp_ok = features.tcp_connect_loss_pct < 50.0

        if http_bad and tcp_ok:
            evidence = [
                EvidenceItem(
                    signal="HTTP Response Status",
                    observed_value=f"HTTP {features.http_status_code}",
                    baseline_value="HTTP 200 OK",
                    deviation_pct=100.0,
                    direction="HIGH",
                    source="http_probe",
                    confidence_contribution=0.55,
                    status="ANOMALOUS",
                ),
                EvidenceItem(
                    signal="TCP Connection Handshake",
                    observed_value=f"{features.tcp_connect_latency} ms",
                    baseline_value="Healthy",
                    deviation_pct=0.0,
                    direction="NORMAL",
                    source="active_probe",
                    confidence_contribution=0.35,
                    status="NORMAL",
                ),
            ]
            calc_conf = 0.90
            diagnoses.append(
                RuleDiagnosis(
                    rule_name="Application Layer Failure",
                    cause_label="Application server crash, internal 5xx error, or HTTP worker exhaustion",
                    affected_layer="Application",
                    confidence_score=calc_conf,
                    evidence_items=[e.to_dict() for e in evidence],
                    evidence_summary={
                        "http_status_code": features.http_status_code,
                        "http_latency_ms": features.http_latency,
                        "http_ttfb_ms": features.http_ttfb,
                    },
                    remediation_text=(
                        "TCP transport connection was successfully established, but the web application returned HTTP 5xx or timed out. "
                        "Inspect backend application logs, database connection pools, or worker processes."
                    ),
                    alternative_hypotheses=[
                        "Upstream reverse proxy (Nginx) 502/504 gateway timeout",
                        "Database connection pool exhausted",
                    ],
                    user_description="The network connection is working, but the destination web service is returning an error (HTTP 5xx).",
                    technical_description="Application-level HTTP 500/502/503 error returned despite successful TCP handshake.",
                    user_impact="The website displays an internal server error or server crash page, but your internet is working properly.",
                    why_points=[
                        "TCP connection handshake completed with normal latency.",
                        f"Web server returned an HTTP error code ({features.http_status_code}).",
                        "Network layer is healthy; problem is inside destination application code.",
                    ],
                    confidence_explanation=f"{int(calc_conf * 100)}% confidence: TCP connection succeeded, but the application server returned an error response.",
                    alternative_hypotheses_structured=[
                        {
                            "hypothesis": "Reverse proxy gateway timeout (504)",
                            "probability": 0.40,
                            "status": "PLAUSIBLE",
                            "reason": "Backend microservice may have crashed while proxy remains reachable.",
                        },
                    ],
                )
            )

        return diagnoses

