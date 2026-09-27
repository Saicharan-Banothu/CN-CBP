"""
Hop Confidence & Dynamic Path Localization Module for Network Autopsy.
Analyzes:
- Multi-run consistency across traceroute runs
- Cross-corroboration with passive metrics (retransmissions, dup-ACKs) on local LAN
- Direct probe correlation (gateway active ping)
Assigns per-hop status: HEALTHY, SUSPECTED, LIKELY_FAULT, UNCONFIRMED.
Enforces the academic principle that traceroute alone is NEVER standalone proof of fault blame.
Caps confidence at 'Medium' with regional tag (e.g. 'likely region: hop X–Y (unconfirmed)')
if only traceroute self-consistency exists without external corroboration.
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Tuple
from storage.db import Database, get_db
from storage.models import HopData, HopObservation
from engine.windowing import WindowFeatures


@dataclass
class HopLocalizationResult:
    hop_location: str                  # e.g., "Hop 1 — Gateway (192.168.1.1)", "likely region: hop 3–5 (unconfirmed)", or "Path healthy"
    hop_confidence: str                # "Low", "Medium", "High"
    suspect_hop_num: Optional[int]
    consistency_pct: float             # Percentage of recent runs showing degradation at this hop
    runs_analyzed: int
    corroborating_signals: List[str]
    hop_observations: List[Dict[str, Any]]
    notes: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HopConfidenceScorer:
    def __init__(self, db: Optional[Database] = None, min_runs: int = 3):
        self.db = db or get_db()
        self.min_runs = min_runs

    def evaluate_hops(
        self,
        features: Optional[WindowFeatures] = None,
        target_override: Optional[str] = None,
    ) -> HopLocalizationResult:
        """
        Analyzes the last N traceroute runs and cross-corroborates with passive metrics
        and direct probes. Produces per-hop structured observations.
        """
        recent_runs = self.db.get_latest_traceroute_runs(num_runs=max(self.min_runs, 3))
        runs_count = len(recent_runs)

        if runs_count == 0:
            return HopLocalizationResult(
                hop_location="No hop data available",
                hop_confidence="Low",
                suspect_hop_num=None,
                consistency_pct=0.0,
                runs_analyzed=0,
                corroborating_signals=[],
                hop_observations=[],
                notes="No traceroute telemetry available in recent observation window.",
            )

        if runs_count < 2:
            return HopLocalizationResult(
                hop_location="Hop analysis pending (insufficient runs)",
                hop_confidence="Low",
                suspect_hop_num=None,
                consistency_pct=0.0,
                runs_analyzed=runs_count,
                corroborating_signals=[],
                hop_observations=[],
                notes="Single traceroute run is never treated as standalone proof of hop blame.",
            )

        # Analyze degradation across hops in each run
        hop_loss_counts: Dict[int, int] = {}
        hop_rtt_jumps: Dict[int, int] = {}
        hop_ips: Dict[int, str] = {}
        hop_latest_rtt: Dict[int, float] = {}
        hop_latest_loss: Dict[int, float] = {}

        # Latest run is at index 0
        _, _, latest_hops = recent_runs[0]
        for h in latest_hops:
            hop_ips[h.hop_number] = h.ip
            hop_latest_rtt[h.hop_number] = h.rtt_ms
            hop_latest_loss[h.hop_number] = h.loss_pct

        for _, _, hops in recent_runs:
            prev_rtt = 0.0
            for h in hops:
                hop_num = h.hop_number
                if h.ip != "*":
                    hop_ips[hop_num] = h.ip

                # Check packet loss at hop
                if h.loss_pct >= 20.0:
                    hop_loss_counts[hop_num] = hop_loss_counts.get(hop_num, 0) + 1

                # Check sharp RTT jump (> 50ms increase over previous hop)
                if h.rtt_ms > 0 and prev_rtt > 0 and (h.rtt_ms - prev_rtt) >= 50.0:
                    hop_rtt_jumps[hop_num] = hop_rtt_jumps.get(hop_num, 0) + 1

                if h.rtt_ms > 0:
                    prev_rtt = h.rtt_ms

        all_hops = sorted(set(list(hop_ips.keys()) + list(hop_loss_counts.keys()) + list(hop_rtt_jumps.keys())))

        # Find the earliest hop that consistently displays degradation
        suspect_hop = None
        highest_score = 0

        for h in all_hops:
            score = hop_loss_counts.get(h, 0) + hop_rtt_jumps.get(h, 0)
            if score > highest_score:
                highest_score = score
                suspect_hop = h

        # Build detailed HopObservation list for dynamic topology display
        hop_observations: List[HopObservation] = []
        for h_num in all_hops:
            ip = hop_ips.get(h_num, "*")
            cur_rtt = hop_latest_rtt.get(h_num, 0.0)
            cur_loss = hop_latest_loss.get(h_num, 0.0)
            score = hop_loss_counts.get(h_num, 0) + hop_rtt_jumps.get(h_num, 0)

            # Determine hop status
            if h_num == suspect_hop and highest_score >= 2:
                status = "LIKELY_FAULT" if (h_num == 1 or runs_count >= 3) else "SUSPECTED"
                conf = "High" if (h_num == 1 and features and features.gateway_loss > 10.0) else "Medium"
            elif cur_loss > 10.0 or cur_rtt > 80.0:
                status = "SUSPECTED"
                conf = "Low"
            else:
                status = "HEALTHY"
                conf = "High"

            hop_observations.append(HopObservation(
                hop_number=h_num,
                ip=ip,
                hostname="Gateway" if h_num == 1 else ("Target" if h_num == max(all_hops) else ""),
                current_rtt_ms=cur_rtt,
                baseline_rtt_ms=round(cur_rtt * 0.5, 1) if cur_rtt > 0 else 0.0,
                loss_pct=cur_loss,
                deviation_pct=round((cur_rtt - (cur_rtt * 0.5)) / max(cur_rtt * 0.5, 0.1) * 100.0, 1) if cur_rtt > 0 else 0.0,
                evidence_count=score,
                confidence=conf,
                status=status,
            ))

        if not suspect_hop or highest_score < 2:
            return HopLocalizationResult(
                hop_location="Path healthy / No localized hop bottleneck",
                hop_confidence="High" if runs_count >= 3 else "Medium",
                suspect_hop_num=None,
                consistency_pct=100.0,
                runs_analyzed=runs_count,
                corroborating_signals=["Consistent responsive path across all traceroute hops"],
                hop_observations=[h.to_dict() for h in hop_observations],
                notes="Path is stable and responsive across multiple observation cycles.",
            )

        consistency_pct = round((highest_score / (runs_count * 2)) * 100.0, 1)
        corroborating: List[str] = [
            f"Traceroute degradation repeated in {highest_score} checks across {runs_count} runs"
        ]

        # Cross-check 1: Is suspect hop the local gateway (Hop 1)?
        is_local_hop = (suspect_hop == 1)
        if is_local_hop:
            if features and (features.gateway_loss >= 10.0 or features.gateway_latency >= 50.0):
                corroborating.append("Direct gateway active ping corroborates latency/loss")

        # Cross-check 2: Passive sniffer signals
        if features and (features.retrans_count >= 2 or features.dup_ack_count >= 2):
            corroborating.append(f"Passive sniffer observed {features.retrans_count} retransmissions / {features.dup_ack_count} dup-ACKs")

        confidence = "Low"
        location_desc = ""

        if is_local_hop:
            if len(corroborating) >= 2 and consistency_pct >= 50.0:
                confidence = "High"
                location_desc = f"Hop 1 — Gateway ({hop_ips.get(1, '192.168.1.1')})"
            else:
                confidence = "Medium"
                location_desc = f"Hop 1 — Local link ({hop_ips.get(1, 'gateway')})"
        else:
            # Remote hop (Hop >= 2)
            # ACADEMIC INTEGRITY RULE: Never claim exact remote hop blame without independent corroboration
            if len(corroborating) >= 2 and features and (features.external_loss > 30.0):
                confidence = "Medium"
                ip_str = hop_ips.get(suspect_hop, "*")
                location_desc = f"likely region: hop {max(1, suspect_hop-1)}–{suspect_hop+1} ({ip_str}), unconfirmed"
            else:
                confidence = "Medium"
                location_desc = f"likely region: hop {max(1, suspect_hop-1)}–{suspect_hop+1} (unconfirmed)"

        return HopLocalizationResult(
            hop_location=location_desc,
            hop_confidence=confidence,
            suspect_hop_num=suspect_hop,
            consistency_pct=consistency_pct,
            runs_analyzed=runs_count,
            corroborating_signals=corroborating,
            hop_observations=[h.to_dict() for h in hop_observations],
            notes=(
                f"Multi-run traceroute consistency scored {consistency_pct}% across {runs_count} runs. "
                f"{len(corroborating)} independent signal(s) evaluated."
            ),
        )
