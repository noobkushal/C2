import hashlib
import os
import secrets
import sqlite3
import uuid
from typing import Any
from src.database.database import get_db_connection, _db_lock
from src.utils.logging_config import logger
from src.utils.time_utils import current_iso8601

def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    """Hashes a password with SHA-256 and a 16-byte salt."""
    if not salt:
        salt = secrets.token_hex(16)
    salted = (salt + password).encode("utf-8")
    pwd_hash = hashlib.sha256(salted).hexdigest()
    return pwd_hash, salt

def init_auth_tables(db_path: str | None = None) -> None:
    """Initializes users and sessions database tables and seeds default accounts idempotently."""
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt          TEXT NOT NULL,
                role          TEXT NOT NULL, -- 'ADMIN' or 'ANALYST'
                created_at    TEXT NOT NULL
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id    TEXT NOT NULL REFERENCES users(user_id),
                created_at TEXT NOT NULL
            );
            """)

            # Seed default Admin and Analyst accounts if empty
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                now = current_iso8601()
                
                # Admin account: admin / Admin@123
                admin_pwd_hash, admin_salt = hash_password("Admin@123")
                cursor.execute("""
                INSERT INTO users (user_id, username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), "admin", admin_pwd_hash, admin_salt, "ADMIN", now))

                # Analyst account: analyst / Analyst@123
                analyst_pwd_hash, analyst_salt = hash_password("Analyst@123")
                cursor.execute("""
                INSERT INTO users (user_id, username, password_hash, salt, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (str(uuid.uuid4()), "analyst", analyst_pwd_hash, analyst_salt, "ANALYST", now))

                conn.commit()
                logger.info("Default Admin (admin) and Analyst (analyst) accounts created.")
        finally:
            conn.close()

def authenticate_user(username: str, password: str, db_path: str | None = None) -> dict[str, Any] | None:
    """Authenticates a user against stored SHA-256 salted password hashes."""
    init_auth_tables(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
        row = cursor.fetchone()
        if not row:
            return None

        stored_hash = row["password_hash"]
        stored_salt = row["salt"]
        calc_hash, _ = hash_password(password, stored_salt)

        if secrets.compare_digest(stored_hash, calc_hash):
            return {
                "user_id": row["user_id"],
                "username": row["username"],
                "role": row["role"],
                "created_at": row["created_at"]
            }
        return None
    finally:
        conn.close()

def create_session(user_id: str, db_path: str | None = None) -> str:
    """Creates a new session token for authenticated user."""
    init_auth_tables(db_path)
    session_id = secrets.token_urlsafe(32)
    now = current_iso8601()
    with _db_lock:
        conn = get_db_connection(db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO sessions (session_id, user_id, created_at)
            VALUES (?, ?, ?)
            """, (session_id, user_id, now))
            conn.commit()
            return session_id
        finally:
            conn.close()

def verify_session(session_id: str, db_path: str | None = None) -> dict[str, Any] | None:
    """Verifies session token and retrieves authenticated user object."""
    if not session_id:
        return None
    init_auth_tables(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT u.user_id, u.username, u.role, u.created_at
        FROM sessions s
        JOIN users u ON s.user_id = u.user_id
        WHERE s.session_id = ?
        """, (session_id,))
        row = cursor.fetchone()
        if row:
            return {
                "user_id": row["user_id"],
                "username": row["username"],
                "role": row["role"],
                "created_at": row["created_at"]
            }
        return None
    finally:
        conn.close()

def has_role(user_obj: dict[str, Any] | None, required_role: str) -> bool:
    """Role-Based Access Control (RBAC) authorization check."""
    if not user_obj:
        return False
    user_role = user_obj.get("role", "").upper()
    if user_role == "ADMIN":
        return True  # ADMIN has superuser privileges
    return user_role == required_role.upper()
