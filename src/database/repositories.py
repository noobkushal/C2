import json
import sqlite3
import pandas as pd
from typing import Any
from src.database.database import get_db_connection, _db_lock
from src.database.models import NetworkEvent, DNSEvent, Alert, Investigation, DetectionRule
from src.utils.logging_config import logger
from src.utils.time_utils import current_iso8601

# --- Network Events Repository ---

def insert_network_event(event: NetworkEvent, db_path: str | None = None) -> bool:
    """Inserts a single network event using parameterized query."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            conn.cursor().execute("""
            INSERT OR IGNORE INTO network_events (
                event_id, timestamp, source_ip, source_port, destination_ip, destination_port,
                protocol, domain, duration, bytes_sent, bytes_received, connection_state,
                log_source, pcap_reference, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, event.to_row())
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to insert network event {event.event_id}: {e}")
            return False
        finally:
            conn.close()

def insert_network_events_batch(events: list[NetworkEvent], db_path: str | None = None) -> int:
    """Inserts a batch of network events using parameterized executemany."""
    if not events:
        return 0
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            rows = [e.to_row() for e in events]
            cursor = conn.cursor()
            cursor.executemany("""
            INSERT OR IGNORE INTO network_events (
                event_id, timestamp, source_ip, source_port, destination_ip, destination_port,
                protocol, domain, duration, bytes_sent, bytes_received, connection_state,
                log_source, pcap_reference, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            logger.error(f"Failed to insert batch of {len(events)} network events: {e}")
            return 0
        finally:
            conn.close()

def get_network_events(
    source_ip: str | None = None,
    destination_ip: str | None = None,
    protocol: str | list[str] | None = None,
    min_port: int | None = None,
    max_port: int | None = None,
    domain: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    log_source: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db_path: str | None = None
) -> pd.DataFrame:
    """Fetches paginated network events matching filters into a DataFrame."""
    query = "SELECT * FROM network_events WHERE 1=1"
    params: list[Any] = []

    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if destination_ip:
        query += " AND destination_ip LIKE ?"
        params.append(f"%{destination_ip}%")
    if protocol:
        if isinstance(protocol, str):
            query += " AND LOWER(protocol) = LOWER(?)"
            params.append(protocol)
        elif isinstance(protocol, list) and protocol:
            query += f" AND LOWER(protocol) IN ({','.join(['?']*len(protocol))})"
            params.extend([p.lower() for p in protocol])
    if min_port is not None:
        query += " AND destination_port >= ?"
        params.append(min_port)
    if max_port is not None:
        query += " AND destination_port <= ?"
        params.append(max_port)
    if domain:
        query += " AND domain LIKE ?"
        params.append(f"%{domain}%")
    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)
    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)
    if log_source:
        query += " AND log_source = ?"
        params.append(log_source)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_db_connection(db_path)
    try:
        df = pd.read_sql_query(query, conn, params=params)
        return df
    finally:
        conn.close()

def get_network_events_count(
    source_ip: str | None = None,
    destination_ip: str | None = None,
    protocol: str | list[str] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    db_path: str | None = None
) -> int:
    """Returns count of network events matching filters."""
    query = "SELECT COUNT(*) FROM network_events WHERE 1=1"
    params: list[Any] = []
    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if destination_ip:
        query += " AND destination_ip LIKE ?"
        params.append(f"%{destination_ip}%")
    if protocol:
        if isinstance(protocol, str):
            query += " AND LOWER(protocol) = LOWER(?)"
            params.append(protocol)
        elif isinstance(protocol, list) and protocol:
            query += f" AND LOWER(protocol) IN ({','.join(['?']*len(protocol))})"
            params.extend([p.lower() for p in protocol])
    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)
    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)

    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        row = cur.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()

# --- DNS Events Repository ---

def insert_dns_events_batch(events: list[DNSEvent], db_path: str | None = None) -> int:
    """Inserts a batch of DNS events using parameterized executemany."""
    if not events:
        return 0
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            rows = [e.to_row() for e in events]
            cursor = conn.cursor()
            cursor.executemany("""
            INSERT OR IGNORE INTO dns_events (
                event_id, timestamp, source_ip, domain, query_type, response, ttl, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)
            conn.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            logger.error(f"Failed to insert batch of {len(events)} DNS events: {e}")
            return 0
        finally:
            conn.close()

def get_dns_events(
    source_ip: str | None = None,
    domain: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db_path: str | None = None
) -> pd.DataFrame:
    """Fetches paginated DNS events into a DataFrame."""
    query = "SELECT * FROM dns_events WHERE 1=1"
    params: list[Any] = []
    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if domain:
        query += " AND domain LIKE ?"
        params.append(f"%{domain}%")
    if start_time:
        query += " AND timestamp >= ?"
        params.append(start_time)
    if end_time:
        query += " AND timestamp <= ?"
        params.append(end_time)

    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_db_connection(db_path)
    try:
        return pd.read_sql_query(query, conn, params=params)
    finally:
        conn.close()

# --- Alerts Repository ---

def upsert_alert(alert: Alert, db_path: str | None = None) -> str:
    """
    Inserts or updates an alert by (source_ip, destination_ip, destination_port, alert_type).
    If an existing alert matches, updates last_seen, risk_score, severity, confidence, reason, evidence, updated_at.
    """
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT alert_id, risk_score, evidence FROM alerts
            WHERE source_ip = ? AND destination_ip = ?
              AND (destination_port = ? OR (destination_port IS NULL AND ? IS NULL))
              AND alert_type = ?
            """, (alert.source_ip, alert.destination_ip, alert.destination_port, alert.destination_port, alert.alert_type))
            existing = cursor.fetchone()

            now = current_iso8601()
            if existing:
                alert_id = existing["alert_id"]
                cursor.execute("""
                UPDATE alerts SET
                    risk_score = max(risk_score, ?),
                    severity = ?,
                    confidence = ?,
                    reason = ?,
                    evidence = ?,
                    last_seen = ?,
                    updated_at = ?
                WHERE alert_id = ?
                """, (alert.risk_score, alert.severity, alert.confidence, alert.reason, alert.evidence, alert.last_seen, now, alert_id))
                conn.commit()
                return alert_id
            else:
                cursor.execute("""
                INSERT INTO alerts (
                    alert_id, timestamp, source_ip, destination_ip, destination_port,
                    alert_type, severity, confidence, risk_score, reason, evidence,
                    status, first_seen, last_seen, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, alert.to_row())
                conn.commit()
                return alert.alert_id
        except sqlite3.Error as e:
            logger.error(f"Failed to upsert alert: {e}")
            raise
        finally:
            conn.close()

def get_alerts(
    status: str | None = None,
    severity: str | None = None,
    alert_type: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db_path: str | None = None
) -> pd.DataFrame:
    """Fetches paginated alerts into a DataFrame."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params: list[Any] = []
    if status and status.upper() != "ALL":
        query += " AND UPPER(status) = UPPER(?)"
        params.append(status)
    if severity and severity.upper() != "ALL":
        query += " AND UPPER(severity) = UPPER(?)"
        params.append(severity)
    if alert_type:
        query += " AND alert_type = ?"
        params.append(alert_type)
    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")
    if destination_ip:
        query += " AND destination_ip LIKE ?"
        params.append(f"%{destination_ip}%")

    query += " ORDER BY risk_score DESC, last_seen DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    conn = get_db_connection(db_path)
    try:
        return pd.read_sql_query(query, conn, params=params)
    finally:
        conn.close()

def get_alert_by_id(alert_id: str, db_path: str | None = None) -> Alert | None:
    """Retrieves an alert by its UUID."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        row = cursor.fetchone()
        if row:
            return Alert.from_row(tuple(row))
        return None
    finally:
        conn.close()

def update_alert_status(alert_id: str, new_status: str, db_path: str | None = None) -> bool:
    """Updates status for an alert."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            now = current_iso8601()
            cursor = conn.cursor()
            cursor.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?", (new_status, now, alert_id))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

# --- Investigations Repository ---

def get_investigation_by_alert_id(alert_id: str, db_path: str | None = None) -> Investigation | None:
    """Gets investigation record for a given alert_id."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM investigations WHERE alert_id = ?", (alert_id,))
        row = cursor.fetchone()
        if row:
            return Investigation.from_row(tuple(row))
        return None
    finally:
        conn.close()

def upsert_investigation(
    alert_id: str,
    verdict: str | None = None,
    new_note: str | None = None,
    analyst_status: str | None = None,
    db_path: str | None = None
) -> Investigation:
    """Upserts an investigation entry, appending timestamped analyst notes."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            now = current_iso8601()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM investigations WHERE alert_id = ?", (alert_id,))
            existing = cursor.fetchone()

            if existing:
                inv = Investigation.from_row(tuple(existing))
                notes_body = inv.notes or ""
                if new_note:
                    formatted_note = f"[{now}] analyst note: {new_note.strip()}"
                    notes_body = f"{notes_body}\n{formatted_note}".strip()
                if analyst_status:
                    inv.analyst_status = analyst_status
                if verdict:
                    inv.verdict = verdict
                inv.notes = notes_body
                inv.updated_at = now

                cursor.execute("""
                UPDATE investigations SET
                    analyst_status = ?, verdict = ?, notes = ?, updated_at = ?
                WHERE investigation_id = ?
                """, (inv.analyst_status, inv.verdict, inv.notes, inv.updated_at, inv.investigation_id))
                conn.commit()
                return inv
            else:
                initial_note = f"[{now}] Investigation opened."
                if new_note:
                    initial_note += f"\n[{now}] analyst note: {new_note.strip()}"
                inv = Investigation(
                    alert_id=alert_id,
                    analyst_status=analyst_status or "INVESTIGATING",
                    verdict=verdict or "UNKNOWN",
                    notes=initial_note,
                    created_at=now,
                    updated_at=now
                )
                cursor.execute("""
                INSERT INTO investigations (
                    investigation_id, alert_id, analyst_status, verdict, notes, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, inv.to_row())
                conn.commit()
                return inv
        finally:
            conn.close()

# --- Detection Rules Repository ---

def get_detection_rules(db_path: str | None = None) -> list[DetectionRule]:
    """Retrieves all detection rules from the DB."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM detection_rules ORDER BY rule_id")
        rows = cursor.fetchall()
        return [DetectionRule.from_row(tuple(r)) for r in rows]
    finally:
        conn.close()

def update_detection_rule(
    rule_id: str,
    enabled: int | None = None,
    threshold: float | None = None,
    db_path: str | None = None
) -> bool:
    """Updates enabled state or threshold for a detection rule."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            now = current_iso8601()
            cursor = conn.cursor()
            query = "UPDATE detection_rules SET updated_at = ?"
            params: list[Any] = [now]
            if enabled is not None:
                query += ", enabled = ?"
                params.append(enabled)
            if threshold is not None:
                query += ", threshold = ?"
                params.append(threshold)
            query += " WHERE rule_id = ?"
            params.append(rule_id)

            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

# --- Analytics Aggregate Repositories ---

def get_overview_kpis(db_path: str | None = None) -> dict[str, int]:
    """Computes all Overview KPIs via efficient aggregate SQL queries."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM network_events")
        ne_count = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts WHERE status NOT IN ('CLOSED', 'FALSE_POSITIVE')")
        active_alerts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts WHERE severity IN ('HIGH', 'CRITICAL') AND status NOT IN ('CLOSED', 'FALSE_POSITIVE')")
        high_crit_alerts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM alerts WHERE alert_type = 'BEACONING'")
        beacon_alerts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(DISTINCT destination_ip) FROM network_events")
        unique_dsts = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM dns_events")
        dns_count = cur.fetchone()[0]

        return {
            "network_events": ne_count,
            "active_alerts": active_alerts,
            "high_critical_alerts": high_crit_alerts,
            "beacon_alerts": beacon_alerts,
            "unique_destinations": unique_dsts,
            "dns_queries": dns_count,
        }
    finally:
        conn.close()
