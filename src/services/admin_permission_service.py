import sqlite3
from src.database.database import get_db_connection, _db_lock
from src.utils.logging_config import logger
from src.utils.time_utils import current_iso8601

def init_admin_permission_tables(db_path: str | None = None) -> None:
    """Initializes admin_permissions table in SQLite database."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_permissions (
                permission_id TEXT PRIMARY KEY,
                permission_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'REVOKED',
                granted_by TEXT,
                granted_at TEXT,
                updated_at TEXT NOT NULL
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS admin_audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                admin_user TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT
            );
            """)
            
            cursor.execute("SELECT COUNT(*) FROM admin_permissions WHERE permission_id = 'REALTIME_SNIFFING'")
            if cursor.fetchone()[0] == 0:
                now = current_iso8601()
                cursor.execute("""
                INSERT INTO admin_permissions (permission_id, permission_name, status, granted_by, granted_at, updated_at)
                VALUES ('REALTIME_SNIFFING', 'Real-Time Packet Sniffing & Monitoring', 'REVOKED', NULL, NULL, ?)
                """, (now,))
            conn.commit()
        finally:
            conn.close()

def get_admin_permission_status(db_path: str | None = None) -> dict:
    """Returns status dictionary for real-time sniffing admin permission."""
    init_admin_permission_tables(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin_permissions WHERE permission_id = 'REALTIME_SNIFFING'")
        row = cursor.fetchone()
        if row:
            return {
                "permission_id": row["permission_id"],
                "permission_name": row["permission_name"],
                "status": row["status"],
                "granted_by": row["granted_by"],
                "granted_at": row["granted_at"],
                "updated_at": row["updated_at"],
                "is_granted": row["status"] == "GRANTED"
            }
        return {"status": "REVOKED", "is_granted": False}
    finally:
        conn.close()

def grant_admin_permission(admin_user: str = "Admin", db_path: str | None = None) -> bool:
    """Grants admin permission for live network packet scanning."""
    init_admin_permission_tables(db_path)
    now = current_iso8601()
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE admin_permissions SET
                status = 'GRANTED',
                granted_by = ?,
                granted_at = ?,
                updated_at = ?
            WHERE permission_id = 'REALTIME_SNIFFING'
            """, (admin_user, now, now))
            
            cursor.execute("""
            INSERT INTO admin_audit_log (action, admin_user, timestamp, details)
            VALUES ('GRANT_PERMISSION', ?, ?, 'Admin granted permission for live real-time packet sniffing')
            """, (admin_user, now))
            conn.commit()
            logger.info(f"Admin permission GRANTED by {admin_user}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error granting permission: {e}")
            return False
        finally:
            conn.close()

def revoke_admin_permission(admin_user: str = "Admin", db_path: str | None = None) -> bool:
    """Revokes admin permission for live network packet scanning."""
    init_admin_permission_tables(db_path)
    now = current_iso8601()
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE admin_permissions SET
                status = 'REVOKED',
                updated_at = ?
            WHERE permission_id = 'REALTIME_SNIFFING'
            """, (now,))
            
            cursor.execute("""
            INSERT INTO admin_audit_log (action, admin_user, timestamp, details)
            VALUES ('REVOKE_PERMISSION', ?, ?, 'Admin revoked permission for live packet sniffing')
            """, (admin_user, now))
            conn.commit()
            logger.info(f"Admin permission REVOKED by {admin_user}")
            return True
        except sqlite3.Error as e:
            logger.error(f"Error revoking permission: {e}")
            return False
        finally:
            conn.close()
