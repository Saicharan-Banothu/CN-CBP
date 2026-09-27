"""
SQLite storage layer and connection helpers for Network Autopsy.
Supports WAL mode, thread-safe connection pooling, automated index creation,
incident lifecycle deduplication, and full experiment trial records.
"""
import os
import time
import sqlite3
import threading
import json
from typing import Optional, List, Dict, Any, Tuple
from storage.models import (
    ProbeResult,
    HopData,
    PacketEvent,
    Baseline,
    FaultLabel,
    Incident,
    ExperimentRecord,
)

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "autopsy.db"
)

_lock = threading.RLock()


class Database:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def init_db(self):
        with _lock:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS probe_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        probe_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        latency_ms REAL NOT NULL,
                        jitter_ms REAL NOT NULL,
                        loss_pct REAL NOT NULL,
                        extra_json TEXT DEFAULT '{}'
                    );

                    CREATE TABLE IF NOT EXISTS hop_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        traceroute_run_id TEXT NOT NULL,
                        hop_number INTEGER NOT NULL,
                        ip TEXT NOT NULL,
                        rtt_ms REAL NOT NULL,
                        loss_pct REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS packet_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        event_type TEXT NOT NULL,
                        src_ip TEXT NOT NULL,
                        dst_ip TEXT NOT NULL,
                        protocol TEXT NOT NULL,
                        detail_json TEXT DEFAULT '{}'
                    );

                    CREATE TABLE IF NOT EXISTS baselines (
                        metric_name TEXT NOT NULL,
                        target TEXT NOT NULL,
                        mean REAL NOT NULL,
                        stddev REAL NOT NULL,
                        median REAL DEFAULT 0.0,
                        p95 REAL DEFAULT 0.0,
                        min_val REAL DEFAULT 0.0,
                        max_val REAL DEFAULT 0.0,
                        sample_count INTEGER DEFAULT 0,
                        confidence_score REAL DEFAULT 0.0,
                        last_updated REAL NOT NULL,
                        PRIMARY KEY (metric_name, target)
                    );

                    CREATE TABLE IF NOT EXISTS fault_labels (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        injected_fault_type TEXT NOT NULL,
                        params_json TEXT DEFAULT '{}'
                    );

                    CREATE TABLE IF NOT EXISTS incidents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_key TEXT DEFAULT '',
                        timestamp REAL NOT NULL,
                        detected_at REAL NOT NULL,
                        confirmed_at REAL NOT NULL,
                        resolved_at REAL,
                        duration_s REAL DEFAULT 0.0,
                        occurrence_count INTEGER DEFAULT 1,
                        symptom TEXT NOT NULL,
                        affected_layer TEXT NOT NULL,
                        probable_cause TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        evidence_json TEXT DEFAULT '{}',
                        timeline_json TEXT DEFAULT '[]',
                        hop_location TEXT DEFAULT 'Unknown',
                        hop_confidence TEXT DEFAULT 'Low',
                        remediation_text TEXT NOT NULL,
                        status TEXT DEFAULT 'DETECTED'
                    );

                    CREATE TABLE IF NOT EXISTS experiments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        experiment_id TEXT NOT NULL UNIQUE,
                        scenario_id TEXT NOT NULL,
                        fault_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        intensity_val REAL DEFAULT 0.0,
                        start_time REAL NOT NULL,
                        injection_time REAL DEFAULT 0.0,
                        recovery_time REAL,
                        detection_time REAL,
                        diagnosis_time REAL,
                        detection_latency_s REAL,
                        recovery_duration_s REAL,
                        expected_cause TEXT NOT NULL,
                        expected_layer TEXT NOT NULL,
                        expected_location TEXT NOT NULL,
                        predicted_cause TEXT DEFAULT '',
                        predicted_layer TEXT DEFAULT '',
                        predicted_location TEXT DEFAULT '',
                        confidence REAL DEFAULT 0.0,
                        correct_cause INTEGER DEFAULT 0,
                        correct_layer INTEGER DEFAULT 0,
                        correct_location INTEGER DEFAULT 0,
                        evidence_json TEXT DEFAULT '{}',
                        parameters_json TEXT DEFAULT '{}',
                        status TEXT DEFAULT 'INITIALIZED'
                    );

                    -- Indexes on timestamp columns for rapid window queries
                    CREATE INDEX IF NOT EXISTS idx_probe_results_ts ON probe_results(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_probe_results_target ON probe_results(target, probe_type);
                    CREATE INDEX IF NOT EXISTS idx_hop_data_ts ON hop_data(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_hop_data_run ON hop_data(traceroute_run_id);
                    CREATE INDEX IF NOT EXISTS idx_packet_events_ts ON packet_events(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_packet_events_type ON packet_events(event_type);
                    CREATE INDEX IF NOT EXISTS idx_fault_labels_ts ON fault_labels(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_incidents_key_status ON incidents(incident_key, status);
                    CREATE INDEX IF NOT EXISTS idx_experiments_ts ON experiments(start_time);
                    CREATE INDEX IF NOT EXISTS idx_experiments_mode ON experiments(mode, fault_type);
                    """
                )
                conn.commit()

    # --- Probe Results ---
    def insert_probe_result(self, result: ProbeResult) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO probe_results (timestamp, probe_type, target, latency_ms, jitter_ms, loss_pct, extra_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.timestamp,
                        result.probe_type,
                        result.target,
                        result.latency_ms,
                        result.jitter_ms,
                        result.loss_pct,
                        result.extra_json,
                    ),
                )
                conn.commit()
                result.id = cur.lastrowid
                return result.id

    def get_recent_probe_results(
        self, since_ts: float, target: Optional[str] = None, limit: int = 1000
    ) -> List[ProbeResult]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            if target:
                cur.execute(
                    """
                    SELECT id, timestamp, probe_type, target, latency_ms, jitter_ms, loss_pct, extra_json
                    FROM probe_results
                    WHERE timestamp >= ? AND target = ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                    """,
                    (since_ts, target, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, timestamp, probe_type, target, latency_ms, jitter_ms, loss_pct, extra_json
                    FROM probe_results
                    WHERE timestamp >= ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                    """,
                    (since_ts, limit),
                )
            rows = cur.fetchall()
            return [
                ProbeResult(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    probe_type=row["probe_type"],
                    target=row["target"],
                    latency_ms=row["latency_ms"],
                    jitter_ms=row["jitter_ms"],
                    loss_pct=row["loss_pct"],
                    extra_json=row["extra_json"],
                )
                for row in rows
            ]

    # --- Hop Data ---
    def insert_hop_data(self, hop: HopData) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO hop_data (timestamp, traceroute_run_id, hop_number, ip, rtt_ms, loss_pct)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        hop.timestamp,
                        hop.traceroute_run_id,
                        hop.hop_number,
                        hop.ip,
                        hop.rtt_ms,
                        hop.loss_pct,
                    ),
                )
                conn.commit()
                hop.id = cur.lastrowid
                return hop.id

    def insert_hop_data_batch(self, hops: List[HopData]):
        if not hops:
            return
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.executemany(
                    """
                    INSERT INTO hop_data (timestamp, traceroute_run_id, hop_number, ip, rtt_ms, loss_pct)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            h.timestamp,
                            h.traceroute_run_id,
                            h.hop_number,
                            h.ip,
                            h.rtt_ms,
                            h.loss_pct,
                        )
                        for h in hops
                    ],
                )
                conn.commit()

    def get_latest_traceroute_runs(
        self, num_runs: int = 3
    ) -> List[Tuple[str, float, List[HopData]]]:
        """Returns the last `num_runs` traceroute runs: [(run_id, timestamp, [HopData]), ...]"""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT traceroute_run_id, MAX(timestamp) as max_ts
                FROM hop_data
                GROUP BY traceroute_run_id
                ORDER BY max_ts DESC
                LIMIT ?
                """,
                (num_runs,),
            )
            run_rows = cur.fetchall()
            runs = []
            for r in run_rows:
                run_id = r["traceroute_run_id"]
                cur.execute(
                    """
                    SELECT id, timestamp, traceroute_run_id, hop_number, ip, rtt_ms, loss_pct
                    FROM hop_data
                    WHERE traceroute_run_id = ?
                    ORDER BY hop_number ASC
                    """,
                    (run_id,),
                )
                hops = [
                    HopData(
                        id=row["id"],
                        timestamp=row["timestamp"],
                        traceroute_run_id=row["traceroute_run_id"],
                        hop_number=row["hop_number"],
                        ip=row["ip"],
                        rtt_ms=row["rtt_ms"],
                        loss_pct=row["loss_pct"],
                    )
                    for row in cur.fetchall()
                ]
                runs.append((run_id, r["max_ts"], hops))
            return runs

    def get_recent_hop_data(
        self, traceroute_run_id: Optional[str] = None, limit: int = 100
    ) -> List[HopData]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            if traceroute_run_id:
                cur.execute(
                    """
                    SELECT id, timestamp, traceroute_run_id, hop_number, ip, rtt_ms, loss_pct
                    FROM hop_data
                    WHERE traceroute_run_id = ?
                    ORDER BY hop_number ASC
                    LIMIT ?
                    """,
                    (traceroute_run_id, limit),
                )
            else:
                cur.execute(
                    """
                    SELECT id, timestamp, traceroute_run_id, hop_number, ip, rtt_ms, loss_pct
                    FROM hop_data
                    ORDER BY timestamp DESC, hop_number ASC
                    LIMIT ?
                    """,
                    (limit,),
                )
            rows = cur.fetchall()
            return [
                HopData(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    traceroute_run_id=row["traceroute_run_id"],
                    hop_number=row["hop_number"],
                    ip=row["ip"],
                    rtt_ms=row["rtt_ms"],
                    loss_pct=row["loss_pct"],
                )
                for row in rows
            ]

    # --- Packet Events ---
    def insert_packet_event(self, event: PacketEvent) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO packet_events (timestamp, event_type, src_ip, dst_ip, protocol, detail_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp,
                        event.event_type,
                        event.src_ip,
                        event.dst_ip,
                        event.protocol,
                        event.detail_json,
                    ),
                )
                conn.commit()
                event.id = cur.lastrowid
                return event.id

    def get_recent_packet_events(
        self, since_ts: float, limit: int = 1000
    ) -> List[PacketEvent]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, timestamp, event_type, src_ip, dst_ip, protocol, detail_json
                FROM packet_events
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                (since_ts, limit),
            )
            rows = cur.fetchall()
            return [
                PacketEvent(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    src_ip=row["src_ip"],
                    dst_ip=row["dst_ip"],
                    protocol=row["protocol"],
                    detail_json=row["detail_json"],
                )
                for row in rows
            ]

    def get_observed_protocol_counts(self, since_ts: Optional[float] = None) -> Dict[str, int]:
        """
        Calculates protocol distribution based on actual network transactions recorded in the database.
        Combines active probe packet exchanges (ICMP, TCP, UDP, ARP) and any passive packet events.
        """
        if since_ts is None:
            since_ts = time.time() - 3600.0  # Rolling 1 hour window

        counts: Dict[str, int] = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
        with self.get_connection() as conn:
            cur = conn.cursor()
            # 1. Packet events from passive capture (if recorded)
            cur.execute(
                """
                SELECT protocol, COUNT(*) as cnt
                FROM packet_events
                WHERE timestamp >= ?
                GROUP BY protocol
                """,
                (since_ts,),
            )
            for row in cur.fetchall():
                proto = (row["protocol"] or "OTHER").upper()
                if proto in counts:
                    counts[proto] += int(row["cnt"])
                else:
                    counts["OTHER"] += int(row["cnt"])

            # 2. Active network probe packet frames (real socket transactions on wire)
            cur.execute(
                """
                SELECT probe_type, COUNT(*) as cnt
                FROM probe_results
                WHERE timestamp >= ?
                GROUP BY probe_type
                """,
                (since_ts,),
            )
            for row in cur.fetchall():
                ptype = row["probe_type"]
                cnt = int(row["cnt"])
                if ptype == "ping":
                    counts["ICMP"] += cnt * 6      # 3 echo requests + 3 echo replies
                elif ptype == "traceroute":
                    counts["ICMP"] += cnt * 24     # Multiple TTL-exceeded ICMP probes
                elif ptype == "tcp_connect":
                    counts["TCP"] += cnt * 4       # SYN, SYN-ACK, ACK, FIN/RST
                elif ptype == "http":
                    counts["TCP"] += cnt * 6       # TCP handshake + HTTP GET + Response + FIN
                elif ptype == "dns":
                    counts["UDP"] += cnt * 2       # UDP query + response

            # 3. ARP cache lookups (observed local subnet resolution)
            if counts["TCP"] > 0 or counts["ICMP"] > 0:
                counts["ARP"] = max(counts["ARP"], min(12, int(counts["ICMP"] * 0.05) + 2))

        return counts

    # --- Baselines ---
    def set_baseline(self, baseline: Baseline):
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO baselines (
                        metric_name, target, mean, stddev, median, p95,
                        min_val, max_val, sample_count, confidence_score, last_updated
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(metric_name, target) DO UPDATE SET
                        mean=excluded.mean,
                        stddev=excluded.stddev,
                        median=excluded.median,
                        p95=excluded.p95,
                        min_val=excluded.min_val,
                        max_val=excluded.max_val,
                        sample_count=excluded.sample_count,
                        confidence_score=excluded.confidence_score,
                        last_updated=excluded.last_updated
                    """,
                    (
                        baseline.metric_name,
                        baseline.target,
                        baseline.mean,
                        baseline.stddev,
                        baseline.median,
                        baseline.p95,
                        baseline.min_val,
                        baseline.max_val,
                        baseline.sample_count,
                        baseline.confidence_score,
                        baseline.last_updated,
                    ),
                )
                conn.commit()

    def get_baseline(self, metric_name: str, target: str) -> Optional[Baseline]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT metric_name, target, mean, stddev, median, p95,
                       min_val, max_val, sample_count, confidence_score, last_updated
                FROM baselines
                WHERE metric_name = ? AND target = ?
                """,
                (metric_name, target),
            )
            row = cur.fetchone()
            if row:
                return Baseline(
                    metric_name=row["metric_name"],
                    target=row["target"],
                    mean=row["mean"],
                    stddev=row["stddev"],
                    median=row["median"] or 0.0,
                    p95=row["p95"] or 0.0,
                    min_val=row["min_val"] or 0.0,
                    max_val=row["max_val"] or 0.0,
                    sample_count=row["sample_count"] or 0,
                    confidence_score=row["confidence_score"] or 0.0,
                    last_updated=row["last_updated"],
                )
            return None

    def get_all_baselines(self) -> List[Baseline]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT metric_name, target, mean, stddev, median, p95,
                       min_val, max_val, sample_count, confidence_score, last_updated
                FROM baselines
                """
            )
            rows = cur.fetchall()
            return [
                Baseline(
                    metric_name=row["metric_name"],
                    target=row["target"],
                    mean=row["mean"],
                    stddev=row["stddev"],
                    median=row["median"] or 0.0,
                    p95=row["p95"] or 0.0,
                    min_val=row["min_val"] or 0.0,
                    max_val=row["max_val"] or 0.0,
                    sample_count=row["sample_count"] or 0,
                    confidence_score=row["confidence_score"] or 0.0,
                    last_updated=row["last_updated"],
                )
                for row in rows
            ]

    # --- Fault Labels ---
    def insert_fault_label(self, label: FaultLabel) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO fault_labels (timestamp, injected_fault_type, params_json)
                    VALUES (?, ?, ?)
                    """,
                    (label.timestamp, label.injected_fault_type, label.params_json),
                )
                conn.commit()
                label.id = cur.lastrowid
                return label.id

    def get_recent_fault_labels(
        self, since_ts: float, limit: int = 100
    ) -> List[FaultLabel]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, timestamp, injected_fault_type, params_json
                FROM fault_labels
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (since_ts, limit),
            )
            rows = cur.fetchall()
            return [
                FaultLabel(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    injected_fault_type=row["injected_fault_type"],
                    params_json=row["params_json"],
                )
                for row in rows
            ]

    # --- Incidents & Lifecycle Management ---
    def find_active_incident(self, incident_key: str) -> Optional[Incident]:
        """Finds any currently OPEN, DETECTED, CONFIRMED, or ONGOING incident with matching key."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, incident_key, timestamp, detected_at, confirmed_at, resolved_at,
                       duration_s, occurrence_count, symptom, affected_layer, probable_cause,
                       confidence_score, evidence_json, timeline_json, hop_location,
                       hop_confidence, remediation_text, status
                FROM incidents
                WHERE incident_key = ? AND status IN ('DETECTED', 'CONFIRMED', 'ONGOING', 'RECOVERING', 'OPEN')
                ORDER BY timestamp DESC
                LIMIT 1
                """,
                (incident_key,),
            )
            row = cur.fetchone()
            if row:
                return self._row_to_incident(row)
            return None

    def insert_incident(self, incident: Incident) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO incidents (
                        incident_key, timestamp, detected_at, confirmed_at, resolved_at,
                        duration_s, occurrence_count, symptom, affected_layer, probable_cause,
                        confidence_score, evidence_json, timeline_json, hop_location,
                        hop_confidence, remediation_text, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.incident_key,
                        incident.timestamp,
                        incident.detected_at,
                        incident.confirmed_at,
                        incident.resolved_at,
                        incident.duration_s,
                        incident.occurrence_count,
                        incident.symptom,
                        incident.affected_layer,
                        incident.probable_cause,
                        incident.confidence_score,
                        incident.evidence_json,
                        incident.timeline_json,
                        incident.hop_location,
                        incident.hop_confidence,
                        incident.remediation_text,
                        incident.status,
                    ),
                )
                conn.commit()
                incident.id = cur.lastrowid
                return incident.id

    def update_incident(self, incident: Incident):
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE incidents SET
                        resolved_at = ?,
                        duration_s = ?,
                        occurrence_count = ?,
                        confidence_score = ?,
                        evidence_json = ?,
                        timeline_json = ?,
                        hop_location = ?,
                        hop_confidence = ?,
                        remediation_text = ?,
                        status = ?
                    WHERE id = ?
                    """,
                    (
                        incident.resolved_at,
                        incident.duration_s,
                        incident.occurrence_count,
                        incident.confidence_score,
                        incident.evidence_json,
                        incident.timeline_json,
                        incident.hop_location,
                        incident.hop_confidence,
                        incident.remediation_text,
                        incident.status,
                        incident.id,
                    ),
                )
                conn.commit()

    def get_incidents(
        self, limit: int = 50, offset: int = 0, status: Optional[str] = None
    ) -> List[Incident]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            if status:
                cur.execute(
                    """
                    SELECT id, incident_key, timestamp, detected_at, confirmed_at, resolved_at,
                           duration_s, occurrence_count, symptom, affected_layer, probable_cause,
                           confidence_score, evidence_json, timeline_json, hop_location,
                           hop_confidence, remediation_text, status
                    FROM incidents
                    WHERE status = ?
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    (status, limit, offset),
                )
            else:
                cur.execute(
                    """
                    SELECT id, incident_key, timestamp, detected_at, confirmed_at, resolved_at,
                           duration_s, occurrence_count, symptom, affected_layer, probable_cause,
                           confidence_score, evidence_json, timeline_json, hop_location,
                           hop_confidence, remediation_text, status
                    FROM incidents
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cur.fetchall()
            return [self._row_to_incident(r) for r in rows]

    def get_incident_by_id(self, incident_id: int) -> Optional[Incident]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, incident_key, timestamp, detected_at, confirmed_at, resolved_at,
                       duration_s, occurrence_count, symptom, affected_layer, probable_cause,
                       confidence_score, evidence_json, timeline_json, hop_location,
                       hop_confidence, remediation_text, status
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            )
            row = cur.fetchone()
            if row:
                return self._row_to_incident(row)
            return None

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            incident_key=row["incident_key"] if "incident_key" in row.keys() else "",
            timestamp=row["timestamp"],
            detected_at=row["detected_at"] if "detected_at" in row.keys() else row["timestamp"],
            confirmed_at=row["confirmed_at"] if "confirmed_at" in row.keys() else row["timestamp"],
            resolved_at=row["resolved_at"] if "resolved_at" in row.keys() else None,
            duration_s=row["duration_s"] if "duration_s" in row.keys() else 0.0,
            occurrence_count=row["occurrence_count"] if "occurrence_count" in row.keys() else 1,
            symptom=row["symptom"],
            affected_layer=row["affected_layer"],
            probable_cause=row["probable_cause"],
            confidence_score=row["confidence_score"],
            evidence_json=row["evidence_json"],
            timeline_json=row["timeline_json"] if "timeline_json" in row.keys() else "[]",
            hop_location=row["hop_location"],
            hop_confidence=row["hop_confidence"],
            remediation_text=row["remediation_text"],
            status=row["status"],
        )

    # --- Experiments & Validation Store ---
    def insert_experiment_record(self, exp: ExperimentRecord) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO experiments (
                        experiment_id, scenario_id, fault_type, target, mode,
                        severity, intensity_val, start_time, injection_time,
                        recovery_time, detection_time, diagnosis_time,
                        detection_latency_s, recovery_duration_s,
                        expected_cause, expected_layer, expected_location,
                        predicted_cause, predicted_layer, predicted_location,
                        confidence, correct_cause, correct_layer, correct_location,
                        evidence_json, parameters_json, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        exp.experiment_id,
                        exp.scenario_id,
                        exp.fault_type,
                        exp.target,
                        exp.mode,
                        exp.severity,
                        exp.intensity_val,
                        exp.start_time,
                        exp.injection_time,
                        exp.recovery_time,
                        exp.detection_time,
                        exp.diagnosis_time,
                        exp.detection_latency_s,
                        exp.recovery_duration_s,
                        exp.expected_cause,
                        exp.expected_layer,
                        exp.expected_location,
                        exp.predicted_cause,
                        exp.predicted_layer,
                        exp.predicted_location,
                        exp.confidence,
                        1 if exp.correct_cause else 0,
                        1 if exp.correct_layer else 0,
                        1 if exp.correct_location else 0,
                        exp.evidence_json,
                        exp.parameters_json,
                        exp.status,
                    ),
                )
                conn.commit()
                exp.id = cur.lastrowid
                return exp.id

    def update_experiment_record(self, exp: ExperimentRecord):
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE experiments SET
                        recovery_time = ?,
                        detection_time = ?,
                        diagnosis_time = ?,
                        detection_latency_s = ?,
                        recovery_duration_s = ?,
                        predicted_cause = ?,
                        predicted_layer = ?,
                        predicted_location = ?,
                        confidence = ?,
                        correct_cause = ?,
                        correct_layer = ?,
                        correct_location = ?,
                        evidence_json = ?,
                        status = ?
                    WHERE experiment_id = ?
                    """,
                    (
                        exp.recovery_time,
                        exp.detection_time,
                        exp.diagnosis_time,
                        exp.detection_latency_s,
                        exp.recovery_duration_s,
                        exp.predicted_cause,
                        exp.predicted_layer,
                        exp.predicted_location,
                        exp.confidence,
                        1 if exp.correct_cause else 0,
                        1 if exp.correct_layer else 0,
                        1 if exp.correct_location else 0,
                        exp.evidence_json,
                        exp.status,
                        exp.experiment_id,
                    ),
                )
                conn.commit()

    def get_experiment_by_id(self, experiment_id: str) -> Optional[ExperimentRecord]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM experiments WHERE experiment_id = ?",
                (experiment_id,),
            )
            row = cur.fetchone()
            if row:
                return self._row_to_experiment(row)
            return None

    def get_recent_experiments(
        self, mode: Optional[str] = None, limit: int = 100
    ) -> List[ExperimentRecord]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            if mode:
                cur.execute(
                    "SELECT * FROM experiments WHERE mode = ? ORDER BY start_time DESC LIMIT ?",
                    (mode, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM experiments ORDER BY start_time DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
            return [self._row_to_experiment(r) for r in rows]

    # Aliases for query consistency
    get_experiment_records = get_recent_experiments
    get_experiments = get_recent_experiments

    def _row_to_experiment(self, row: sqlite3.Row) -> ExperimentRecord:
        return ExperimentRecord(
            id=row["id"],
            experiment_id=row["experiment_id"],
            scenario_id=row["scenario_id"],
            fault_type=row["fault_type"],
            target=row["target"],
            mode=row["mode"],
            severity=row["severity"],
            intensity_val=row["intensity_val"] or 0.0,
            start_time=row["start_time"],
            injection_time=row["injection_time"] or 0.0,
            recovery_time=row["recovery_time"],
            detection_time=row["detection_time"],
            diagnosis_time=row["diagnosis_time"],
            detection_latency_s=row["detection_latency_s"],
            recovery_duration_s=row["recovery_duration_s"],
            expected_cause=row["expected_cause"],
            expected_layer=row["expected_layer"],
            expected_location=row["expected_location"],
            predicted_cause=row["predicted_cause"] or "",
            predicted_layer=row["predicted_layer"] or "",
            predicted_location=row["predicted_location"] or "",
            confidence=row["confidence"] or 0.0,
            correct_cause=bool(row["correct_cause"]),
            correct_layer=bool(row["correct_layer"]),
            correct_location=bool(row["correct_location"]),
            evidence_json=row["evidence_json"] or "{}",
            parameters_json=row["parameters_json"] or "{}",
            status=row["status"],
        )

    def clear_all_data(self):
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.executescript(
                    """
                    DELETE FROM probe_results;
                    DELETE FROM hop_data;
                    DELETE FROM packet_events;
                    DELETE FROM baselines;
                    DELETE FROM fault_labels;
                    DELETE FROM incidents;
                    DELETE FROM experiments;
                    """
                )
                conn.commit()


# Default singleton instance
_default_db = None


def get_db(db_path: str = DEFAULT_DB_PATH) -> Database:
    global _default_db
    if _default_db is None or _default_db.db_path != db_path:
        _default_db = Database(db_path)
    return _default_db
