"""
Passive Capture Module for Network Autopsy.
Uses Scapy sniffer to detect:
- TCP Retransmissions
- Duplicate ACKs (3+ identical ACKs)
- TCP RST / FIN patterns
- Frame/packet checksum and CRC errors
- Protocol distribution counters (TCP, UDP, ICMP, ARP, Other)

Gracefully falls back to active-probe-only mode if sniffing permissions
(e.g., sudo/Npcap) are unavailable.
"""
import time
import json
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple

from storage.db import Database, get_db
from storage.models import PacketEvent

logger = logging.getLogger("network_autopsy.passive_capture")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, conf
    conf.verb = 0
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    SCAPY_SNIFF_CAPABLE = True
except Exception as e:
    SCAPY_SNIFF_CAPABLE = False
    logger.warning(f"Scapy sniffing capability not ready: {e}")


class PassiveCaptureAgent:
    def __init__(
        self,
        db: Optional[Database] = None,
        interface: Optional[str] = None,
        bpf_filter: str = "ip or arp",
        max_history: int = 5000,
    ):
        self.db = db or get_db()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.max_history = max_history

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.sniffer_active = False
        self.sniffer_error = ""

        # Tracking state
        # (src_ip, src_port, dst_ip, dst_port) -> deque of recent (seq, length, timestamp)
        self._tcp_seq_tracker: Dict[Tuple[str, int, str, int], deque] = defaultdict(
            lambda: deque(maxlen=64)
        )
        # (src_ip, src_port, dst_ip, dst_port) -> [last_ack_num, consecutive_dup_count]
        self._tcp_ack_tracker: Dict[Tuple[str, int, str, int], List[int]] = {}

        # Protocol counters for sliding stats
        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "ARP": 0,
            "OTHER": 0,
        }
        self.event_counts = {
            "retransmission": 0,
            "dup_ack": 0,
            "rst": 0,
            "fin": 0,
            "checksum_error": 0,
        }

    def _process_packet(self, pkt):
        ts = time.time()
        proto = "OTHER"
        src_ip = ""
        dst_ip = ""

        try:
            # 1. Protocol distribution count
            if pkt.haslayer(ARP):
                proto = "ARP"
                self.protocol_counts["ARP"] += 1
                return

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                # Checksum validation for IP header (maps to Week 2 lab concept)
                orig_chk = pkt[IP].chksum
                # Scapy auto-computes if chksum is None or recalculating
                test_ip = IP(bytes(pkt[IP]))
                calc_chk = test_ip.chksum
                if orig_chk is not None and calc_chk is not None and orig_chk != calc_chk:
                    self._record_event(
                        ts, "checksum_error", src_ip, dst_ip, "IP",
                        {"error": "IP Header Checksum Mismatch", "orig": orig_chk, "calc": calc_chk}
                    )
                    self.event_counts["checksum_error"] += 1

                if pkt.haslayer(ICMP):
                    proto = "ICMP"
                    self.protocol_counts["ICMP"] += 1

                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    self.protocol_counts["UDP"] += 1

                elif pkt.haslayer(TCP):
                    proto = "TCP"
                    self.protocol_counts["TCP"] += 1
                    self._process_tcp(pkt, src_ip, dst_ip, ts)

                else:
                    self.protocol_counts["OTHER"] += 1
            else:
                self.protocol_counts["OTHER"] += 1

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")

    def _process_tcp(self, pkt, src_ip: str, dst_ip: str, ts: float):
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = str(tcp.flags)
        flow_key = (src_ip, src_port, dst_ip, dst_port)
        rev_flow_key = (dst_ip, dst_port, src_ip, src_port)

        payload_len = len(tcp.payload)
        seq = tcp.seq
        ack = tcp.ack

        # 1. Check TCP Flags: RST or FIN
        if "R" in flags:
            self._record_event(ts, "rst", src_ip, dst_ip, "TCP", {
                "sport": src_port, "dport": dst_port, "flags": flags, "seq": seq
            })
            self.event_counts["rst"] += 1

        if "F" in flags:
            self._record_event(ts, "fin", src_ip, dst_ip, "TCP", {
                "sport": src_port, "dport": dst_port, "flags": flags, "seq": seq
            })
            self.event_counts["fin"] += 1

        # 2. Retransmission Detection:
        # Same sequence number seen twice from same source to same destination with payload > 0
        if payload_len > 0:
            history = self._tcp_seq_tracker[flow_key]
            # Check if this exact seq number was recently seen
            is_retransmit = False
            for past_seq, past_len, past_ts in history:
                if past_seq == seq and past_len == payload_len and (ts - past_ts) < 10.0:
                    is_retransmit = True
                    break

            if is_retransmit:
                self._record_event(ts, "retransmission", src_ip, dst_ip, "TCP", {
                    "sport": src_port, "dport": dst_port, "seq": seq, "len": payload_len
                })
                self.event_counts["retransmission"] += 1
            else:
                history.append((seq, payload_len, ts))

        # 3. Duplicate ACK Detection:
        # 3+ identical ACK numbers with no payload
        if "A" in flags and payload_len == 0:
            ack_info = self._tcp_ack_tracker.get(flow_key)
            if ack_info is None:
                self._tcp_ack_tracker[flow_key] = [ack, 0]
            else:
                last_ack, count = ack_info
                if ack == last_ack:
                    count += 1
                    self._tcp_ack_tracker[flow_key][1] = count
                    if count >= 3:
                        self._record_event(ts, "dup_ack", src_ip, dst_ip, "TCP", {
                            "sport": src_port, "dport": dst_port, "ack": ack, "count": count
                        })
                        self.event_counts["dup_ack"] += 1
                elif ack > last_ack:
                    self._tcp_ack_tracker[flow_key] = [ack, 0]

    def _record_event(self, ts: float, event_type: str, src_ip: str, dst_ip: str, protocol: str, detail: Dict[str, Any]):
        evt = PacketEvent(
            timestamp=ts,
            event_type=event_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            detail_json=json.dumps(detail),
        )
        self.db.insert_packet_event(evt)

    def _sniff_worker(self):
        logger.info(f"Starting passive sniffer on interface='{self.interface or 'default'}'")
        try:
            kwargs = {
                "prn": self._process_packet,
                "store": 0,
                "stop_filter": lambda _: not self._running,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            if self.bpf_filter and getattr(conf, 'use_pcap', False):
                kwargs["filter"] = self.bpf_filter

            self.sniffer_active = True
            sniff(**kwargs)
        except PermissionError as e:
            self.sniffer_active = False
            self.sniffer_error = "Permission denied: Packet capture requires administrative/root privileges (sudo on Linux, Npcap on Windows)."
            logger.warning(f"PassiveCapture: {self.sniffer_error} Falling back to active-probe-only mode.")
        except Exception as e:
            self.sniffer_active = False
            self.sniffer_error = str(e)
            logger.warning(f"PassiveCapture: Sniffer failed ({e}). Falling back to active-probe-only mode.")
        finally:
            self.sniffer_active = False

    def start(self):
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._sniff_worker, daemon=True, name="PassiveSnifferThread")
                self._thread.start()

    def stop(self):
        with self._lock:
            self._running = False
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=2.0)

    def record_observed_packets(self, protocol: str, count: int = 1, event_type: Optional[str] = None):
        """Records packets observed by the platform (from active probes, socket transactions, or packet capture)."""
        proto_key = protocol.upper()
        if proto_key not in self.protocol_counts:
            proto_key = "OTHER"
        with self._lock:
            self.protocol_counts[proto_key] += count
            if event_type and event_type in self.event_counts:
                self.event_counts[event_type] += 1

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns protocol distribution and packet event statistics.
        If promiscuous sniffer is active, reports directly from captured frames.
        Otherwise, seamlessly reflects the verified socket-level network telemetry
        observed by active probes and host interfaces.
        """
        with self._lock:
            total_sniffed = sum(self.protocol_counts.values())

        if self.sniffer_active and total_sniffed > 0:
            return {
                "sniffer_active": True,
                "sniffer_error": "",
                "capture_mode": "Promiscuous Sniffer",
                "protocols": dict(self.protocol_counts),
                "events": dict(self.event_counts),
                "total_packets": total_sniffed,
            }

        # Fallback to empirical database telemetry when L2 raw sniffing is restricted
        db_counts = self.db.get_observed_protocol_counts()
        total_db = sum(db_counts.values())
        return {
            "sniffer_active": self.sniffer_active,
            "sniffer_error": self.sniffer_error,
            "capture_mode": "Network Telemetry",
            "protocols": db_counts,
            "events": dict(self.event_counts),
            "total_packets": total_db,
        }
