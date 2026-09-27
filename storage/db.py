"""
SQLite storage layer and connection helpers for Network Autopsy.
"""
import os
import sqlite3
import threading
from typing import Optional, List, Dict, Any, Tuple
from storage.models import (
    ProbeResult,
    HopData,
    PacketEvent,
    Baseline,
    FaultLabel,
    Incident,
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
                        timestamp REAL NOT NULL,
                        symptom TEXT NOT NULL,
                        affected_layer TEXT NOT NULL,
                        probable_cause TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        evidence_json TEXT DEFAULT '{}',
                        hop_location TEXT DEFAULT 'Unknown',
                        hop_confidence TEXT DEFAULT 'Low',
                        remediation_text TEXT NOT NULL,
                        status TEXT DEFAULT 'OPEN'
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

    # --- Baselines ---
    def set_baseline(self, baseline: Baseline):
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO baselines (metric_name, target, mean, stddev, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(metric_name, target) DO UPDATE SET
                        mean=excluded.mean,
                        stddev=excluded.stddev,
                        last_updated=excluded.last_updated
                    """,
                    (
                        baseline.metric_name,
                        baseline.target,
                        baseline.mean,
                        baseline.stddev,
                        baseline.last_updated,
                    ),
                )
                conn.commit()

    def get_baseline(self, metric_name: str, target: str) -> Optional[Baseline]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT metric_name, target, mean, stddev, last_updated
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
                    last_updated=row["last_updated"],
                )
            return None

    def get_all_baselines(self) -> List[Baseline]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT metric_name, target, mean, stddev, last_updated FROM baselines")
            rows = cur.fetchall()
            return [
                Baseline(
                    metric_name=row["metric_name"],
                    target=row["target"],
                    mean=row["mean"],
                    stddev=row["stddev"],
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

    def get_all_fault_labels(self, limit: int = 1000) -> List[FaultLabel]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, timestamp, injected_fault_type, params_json
                FROM fault_labels
                ORDER BY timestamp ASC
                LIMIT ?
                """,
                (limit,),
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

    # --- Incidents ---
    def insert_incident(self, incident: Incident) -> int:
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO incidents (
                        timestamp, symptom, affected_layer, probable_cause,
                        confidence_score, evidence_json, hop_location,
                        hop_confidence, remediation_text, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        incident.timestamp,
                        incident.symptom,
                        incident.affected_layer,
                        incident.probable_cause,
                        incident.confidence_score,
                        incident.evidence_json,
                        incident.hop_location,
                        incident.hop_confidence,
                        incident.remediation_text,
                        incident.status,
                    ),
                )
                conn.commit()
                incident.id = cur.lastrowid
                return incident.id

    def get_incidents(
        self, limit: int = 50, offset: int = 0, status: Optional[str] = None
    ) -> List[Incident]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            if status:
                cur.execute(
                    """
                    SELECT id, timestamp, symptom, affected_layer, probable_cause,
                           confidence_score, evidence_json, hop_location,
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
                    SELECT id, timestamp, symptom, affected_layer, probable_cause,
                           confidence_score, evidence_json, hop_location,
                           hop_confidence, remediation_text, status
                    FROM incidents
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cur.fetchall()
            return [
                Incident(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    symptom=row["symptom"],
                    affected_layer=row["affected_layer"],
                    probable_cause=row["probable_cause"],
                    confidence_score=row["confidence_score"],
                    evidence_json=row["evidence_json"],
                    hop_location=row["hop_location"],
                    hop_confidence=row["hop_confidence"],
                    remediation_text=row["remediation_text"],
                    status=row["status"],
                )
                for row in rows
            ]

    def get_incident_by_id(self, incident_id: int) -> Optional[Incident]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, timestamp, symptom, affected_layer, probable_cause,
                       confidence_score, evidence_json, hop_location,
                       hop_confidence, remediation_text, status
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            )
            row = cur.fetchone()
            if row:
                return Incident(
                    id=row["id"],
                    timestamp=row["timestamp"],
                    symptom=row["symptom"],
                    affected_layer=row["affected_layer"],
                    probable_cause=row["probable_cause"],
                    confidence_score=row["confidence_score"],
                    evidence_json=row["evidence_json"],
                    hop_location=row["hop_location"],
                    hop_confidence=row["hop_confidence"],
                    remediation_text=row["remediation_text"],
                    status=row["status"],
                )
            return None

    def update_incident_status(self, incident_id: int, status: str):
        with _lock:
            with self.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "UPDATE incidents SET status = ? WHERE id = ?",
                    (status, incident_id),
                )
                conn.commit()

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
