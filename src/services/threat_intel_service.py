"""
Threat Intelligence Enrichment Service — NetSentry SOC
Provides IP reputation lookups via AbuseIPDB and/or VirusTotal.
API keys are stored in the SQLite database (threat_intel_config table).
Results are cached in-process to avoid redundant API calls.
"""
import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Optional
from src.utils.logging_config import logger

# ─── In-process cache (ip → (result, expiry_epoch)) ──────────────────────────
_CACHE: dict[str, tuple[dict, float]] = {}
_CACHE_TTL_SECONDS = 3600  # 1-hour cache


def _cache_key(ip: str, provider: str) -> str:
    return hashlib.md5(f"{provider}:{ip}".encode()).hexdigest()


def _cached_get(ip: str, provider: str) -> Optional[dict]:
    key = _cache_key(ip, provider)
    entry = _CACHE.get(key)
    if entry and time.time() < entry[1]:
        return entry[0]
    return None


def _cache_set(ip: str, provider: str, result: dict):
    key = _cache_key(ip, provider)
    _CACHE[key] = (result, time.time() + _CACHE_TTL_SECONDS)


# ─── DB helpers for API key storage ──────────────────────────────────────────
def _ensure_config_table():
    from src.database.database import get_db_connection, _db_lock
    with _db_lock:
        conn = get_db_connection()
        conn.cursor().execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_config (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""")
        conn.commit()
        conn.close()


def get_api_key(name: str) -> Optional[str]:
    """Retrieves an API key by name from the DB."""
    _ensure_config_table()
    from src.database.database import get_db_connection
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT value FROM threat_intel_config WHERE key = ?", (name,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None


def set_api_key(name: str, value: str):
    """Stores or updates an API key in the DB."""
    _ensure_config_table()
    from src.database.database import get_db_connection, _db_lock
    with _db_lock:
        conn = get_db_connection()
        conn.cursor().execute(
            "INSERT OR REPLACE INTO threat_intel_config (key, value) VALUES (?, ?)",
            (name, value)
        )
        conn.commit()
        conn.close()


def delete_api_key(name: str):
    """Removes an API key from the DB."""
    _ensure_config_table()
    from src.database.database import get_db_connection, _db_lock
    with _db_lock:
        conn = get_db_connection()
        conn.cursor().execute("DELETE FROM threat_intel_config WHERE key = ?", (name,))
        conn.commit()
        conn.close()


# ─── AbuseIPDB lookup ─────────────────────────────────────────────────────────
def lookup_abuseipdb(ip: str, api_key: str) -> dict:
    """
    Queries AbuseIPDB v2 /check endpoint.
    Returns a normalised result dict with keys:
        ip, abuse_confidence_score, country_code, isp, domain,
        total_reports, last_reported_at, is_whitelisted, provider
    """
    cached = _cached_get(ip, "abuseipdb")
    if cached:
        return cached

    try:
        import urllib.request
        url = (
            f"https://api.abuseipdb.com/api/v2/check"
            f"?ipAddress={ip}&maxAgeInDays=90&verbose"
        )
        req = urllib.request.Request(url)
        req.add_header("Key", api_key)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        data = body.get("data", {})
        result = {
            "provider":               "AbuseIPDB",
            "ip":                     ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code":           data.get("countryCode", "?"),
            "isp":                    data.get("isp", "?"),
            "domain":                 data.get("domain", "?"),
            "total_reports":          data.get("totalReports", 0),
            "last_reported_at":       data.get("lastReportedAt", None),
            "is_whitelisted":         data.get("isWhitelisted", False),
            "is_public":              data.get("isPublic", True),
            "error":                  None,
        }
        _cache_set(ip, "abuseipdb", result)
        return result

    except Exception as e:
        err = str(e)
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {err}")
        result = {"provider": "AbuseIPDB", "ip": ip, "error": err}
        return result


# ─── VirusTotal lookup ────────────────────────────────────────────────────────
def lookup_virustotal(ip: str, api_key: str) -> dict:
    """
    Queries VirusTotal v3 /ip_addresses/{ip} endpoint.
    Returns normalised dict with keys:
        ip, malicious_votes, suspicious_votes, harmless_votes, undetected_votes,
        country, as_owner, reputation, last_analysis_date, provider
    """
    cached = _cached_get(ip, "virustotal")
    if cached:
        return cached

    try:
        import urllib.request
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        req = urllib.request.Request(url)
        req.add_header("x-apikey", api_key)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result = {
            "provider":           "VirusTotal",
            "ip":                 ip,
            "malicious_votes":    stats.get("malicious", 0),
            "suspicious_votes":   stats.get("suspicious", 0),
            "harmless_votes":     stats.get("harmless", 0),
            "undetected_votes":   stats.get("undetected", 0),
            "country":            attrs.get("country", "?"),
            "as_owner":           attrs.get("as_owner", "?"),
            "reputation":         attrs.get("reputation", 0),
            "last_analysis_date": attrs.get("last_analysis_date", None),
            "error":              None,
        }
        _cache_set(ip, "virustotal", result)
        return result

    except Exception as e:
        err = str(e)
        logger.warning(f"VirusTotal lookup failed for {ip}: {err}")
        return {"provider": "VirusTotal", "ip": ip, "error": err}


# ─── Unified enrichment entry point ──────────────────────────────────────────
def enrich_ip(ip: str) -> list[dict]:
    """
    Runs all configured threat intel providers for the given IP.
    Returns list of result dicts (one per active provider).
    Empty list if no API keys are configured.
    """
    results = []

    abuse_key = get_api_key("ABUSEIPDB_API_KEY")
    if abuse_key:
        results.append(lookup_abuseipdb(ip, abuse_key))

    vt_key = get_api_key("VIRUSTOTAL_API_KEY")
    if vt_key:
        results.append(lookup_virustotal(ip, vt_key))

    return results


def clear_cache():
    """Clears the in-process threat intel cache."""
    global _CACHE
    _CACHE = {}

