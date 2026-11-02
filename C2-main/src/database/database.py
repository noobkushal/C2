import os
import sqlite3
import threading
from src.utils.config_loader import load_app_config, load_detection_rules
from src.utils.logging_config import logger
from src.utils.time_utils import current_iso8601

_db_lock = threading.Lock()

def get_db_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Returns a SQLite connection guarded by check_same_thread=False for Streamlit compatibility."""
    if db_path is None:
        cfg = load_app_config()
        db_path = cfg["application"]["db_path"]
    
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str | None = None) -> None:
    """Initializes the database schema and seeds initial detection rules idempotently."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            
            # network_events table & indexes
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                event_id        TEXT PRIMARY KEY,
                timestamp       TEXT NOT NULL,
                source_ip       TEXT NOT NULL,
                source_port     INTEGER,
                destination_ip  TEXT NOT NULL,
                destination_port INTEGER,
                protocol        TEXT,
                domain          TEXT,
                duration        REAL,
                bytes_sent      INTEGER DEFAULT 0,
                bytes_received  INTEGER DEFAULT 0,
                connection_state TEXT,
                log_source      TEXT NOT NULL,
                pcap_reference  TEXT,
                created_at      TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ne_timestamp ON network_events(timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ne_src_ip ON network_events(source_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ne_dst_ip ON network_events(destination_ip);")
            
            # dns_events table & indexes
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_events (
                event_id     TEXT PRIMARY KEY,
                timestamp    TEXT NOT NULL,
                source_ip    TEXT NOT NULL,
                domain       TEXT NOT NULL,
                query_type   TEXT,
                response     TEXT,
                ttl          REAL,
                created_at   TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_events(domain);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_src ON dns_events(source_ip);")
            
            # alerts table & indexes
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id          TEXT PRIMARY KEY,
                timestamp         TEXT NOT NULL,
                source_ip         TEXT NOT NULL,
                destination_ip    TEXT NOT NULL,
                destination_port  INTEGER,
                alert_type        TEXT NOT NULL,
                severity          TEXT NOT NULL,
                confidence        REAL,
                risk_score        INTEGER NOT NULL,
                reason            TEXT NOT NULL,
                evidence          TEXT,
                status            TEXT NOT NULL DEFAULT 'NEW',
                first_seen        TEXT NOT NULL,
                last_seen         TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                updated_at        TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_type ON alerts(alert_type);")
            
            # investigations table & index
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id  TEXT PRIMARY KEY,
                alert_id          TEXT NOT NULL REFERENCES alerts(alert_id),
                analyst_status     TEXT,
                verdict            TEXT,
                notes              TEXT,
                created_at          TEXT NOT NULL,
                updated_at          TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_inv_alert ON investigations(alert_id);")
            
            # detection_rules table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id        TEXT PRIMARY KEY,
                name           TEXT NOT NULL,
                description    TEXT,
                enabled        INTEGER NOT NULL DEFAULT 1,
                severity       TEXT,
                threshold      REAL,
                configuration  TEXT,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            );
            """)
            
            # Seed detection_rules if empty
            cursor.execute("SELECT COUNT(*) FROM detection_rules")
            if cursor.fetchone()[0] == 0:
                rules_cfg = load_detection_rules()
                now = current_iso8601()
                default_rules = [
                    ("RULE_BEACON", "C2 Beaconing Detector", "Identifies regular-interval connection patterns", 1, "HIGH", rules_cfg["beacon"]["max_cv"], "{}", now, now),
                    ("RULE_DNS_LONG", "DNS Long Domain Detector", "Identifies unusually long domain names", 1, "MEDIUM", float(rules_cfg["dns"]["long_domain_length"]), "{}", now, now),
                    ("RULE_DNS_FREQ", "DNS High Frequency Detector", "Identifies excessive DNS query volumes", 1, "MEDIUM", float(rules_cfg["dns"]["high_frequency_threshold"]), "{}", now, now),
                    ("RULE_DNS_SUBDOM", "DNS Subdomain Tunneling", "Identifies excessive unique subdomains under base domain", 1, "HIGH", float(rules_cfg["dns"]["max_unique_subdomains"]), "{}", now, now),
                    ("RULE_RARE_DEST", "Rare Destination Detector", "Identifies connections to rarely-contacted external IPs", 1, "MEDIUM", rules_cfg["rare_destination"]["max_occurrence_pct"], "{}", now, now),
                    ("RULE_CONN_FREQ", "High Connection Frequency", "Identifies high connections per minute from a single source", 1, "LOW", float(rules_cfg["connection_frequency"]["threshold_per_minute"]), "{}", now, now),
                    ("RULE_SUSP_PORT", "Suspicious Port Detector", "Identifies traffic on non-standard/commonly abused ports", 1, "LOW", 0.0, "{}", now, now),
                ]
                cursor.executemany("""
                INSERT INTO detection_rules (rule_id, name, description, enabled, severity, threshold, configuration, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, default_rules)
                
            conn.commit()
            logger.info(f"Database initialized successfully at {db_path or 'default path'}")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
        finally:
            conn.close()
