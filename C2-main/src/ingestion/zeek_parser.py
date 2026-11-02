import os
import re
from typing import Iterator, Any
from src.database.models import NetworkEvent, DNSEvent
from src.utils.logging_config import logger
from src.utils.time_utils import epoch_to_iso8601

def parse_zeek_log(filepath: str) -> Iterator[dict[str, Any]]:
    """
    Reads Zeek TSV log. Dynamically parses header (#separator, #fields).
    Yields dict per row with cleaned sentinel values and ISO 8601 timestamps.
    """
    if not os.path.exists(filepath):
        logger.warning(f"Zeek log file not found: {filepath}")
        return

    if os.path.getsize(filepath) == 0:
        logger.warning(f"Zeek log file is empty: {filepath}")
        return

    separator = "\t"
    fields: list[str] = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue

                if line.startswith("#"):
                    if line.startswith("#separator"):
                        parts = line.split(maxsplit=1)
                        if len(parts) == 2:
                            sep_val = parts[1]
                            if sep_val.startswith("\\x"):
                                try:
                                    separator = chr(int(sep_val[2:], 16))
                                except ValueError:
                                    separator = "\t"
                            else:
                                separator = sep_val
                    elif line.startswith("#fields"):
                        fields = line.split(separator)[1:]
                    continue

                if not fields:
                    logger.warning(f"Zeek log {filepath} missing #fields header before data lines.")
                    return

                values = line.split(separator)
                if len(values) != len(fields):
                    logger.warning(
                        f"Malformed row in {filepath}: field count mismatch "
                        f"(expected {len(fields)}, got {len(values)}). Skipping row."
                    )
                    continue

                row_dict = {}
                for field_name, raw_val in zip(fields, values):
                    if raw_val in ("-", "(empty)", "(unset)"):
                        row_dict[field_name] = None
                    else:
                        row_dict[field_name] = raw_val

                # Convert epoch timestamp if present
                if "ts" in row_dict and row_dict["ts"] is not None:
                    try:
                        row_dict["iso_timestamp"] = epoch_to_iso8601(row_dict["ts"])
                    except ValueError:
                        logger.warning(f"Non-numeric timestamp ts={row_dict['ts']} in {filepath}. Skipping row.")
                        continue

                yield row_dict
    except Exception as e:
        logger.warning(f"Failed to read/parse Zeek log {filepath}: {e}")
        return

def _safe_int(val: Any) -> int | None:
    if val is None:
        return None
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return None

def _safe_float(val: Any) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None

def map_conn_row(row: dict[str, Any], pcap_reference: str | None = None) -> NetworkEvent | None:
    """Maps a parsed conn.log dict to NetworkEvent."""
    ts = row.get("iso_timestamp")
    src_ip = row.get("id.orig_h")
    dst_ip = row.get("id.resp_h")
    if not ts or not src_ip or not dst_ip:
        return None

    return NetworkEvent(
        timestamp=ts,
        source_ip=src_ip,
        source_port=_safe_int(row.get("id.orig_p")),
        destination_ip=dst_ip,
        destination_port=_safe_int(row.get("id.resp_p")),
        protocol=row.get("proto"),
        duration=_safe_float(row.get("duration")),
        bytes_sent=_safe_int(row.get("orig_bytes")) or 0,
        bytes_received=_safe_int(row.get("resp_bytes")) or 0,
        connection_state=row.get("conn_state"),
        log_source="conn",
        pcap_reference=pcap_reference
    )

def map_dns_row(row: dict[str, Any]) -> DNSEvent | None:
    """Maps a parsed dns.log dict to DNSEvent."""
    ts = row.get("iso_timestamp")
    src_ip = row.get("id.orig_h")
    domain = row.get("query")
    if not ts or not src_ip or not domain:
        return None

    ans = row.get("answers")
    if isinstance(ans, list):
        ans_str = ",".join(str(a) for a in ans)
    else:
        ans_str = str(ans) if ans is not None else None

    return DNSEvent(
        timestamp=ts,
        source_ip=src_ip,
        domain=domain,
        query_type=row.get("qtype_name") or row.get("qtype"),
        response=ans_str,
        ttl=_safe_float(row.get("TTL") or row.get("ttl"))
    )

def map_http_row(row: dict[str, Any], pcap_reference: str | None = None) -> NetworkEvent | None:
    """Maps a parsed http.log dict to NetworkEvent."""
    ts = row.get("iso_timestamp")
    src_ip = row.get("id.orig_h")
    dst_ip = row.get("id.resp_h")
    if not ts or not src_ip or not dst_ip:
        return None

    return NetworkEvent(
        timestamp=ts,
        source_ip=src_ip,
        source_port=_safe_int(row.get("id.orig_p")),
        destination_ip=dst_ip,
        destination_port=_safe_int(row.get("id.resp_p")),
        protocol="tcp",
        domain=row.get("host"),
        log_source="http",
        pcap_reference=pcap_reference
    )

def map_ssl_row(row: dict[str, Any], pcap_reference: str | None = None) -> NetworkEvent | None:
    """Maps a parsed ssl.log dict to NetworkEvent."""
    ts = row.get("iso_timestamp")
    src_ip = row.get("id.orig_h")
    dst_ip = row.get("id.resp_h")
    if not ts or not src_ip or not dst_ip:
        return None

    return NetworkEvent(
        timestamp=ts,
        source_ip=src_ip,
        source_port=_safe_int(row.get("id.orig_p")),
        destination_ip=dst_ip,
        destination_port=_safe_int(row.get("id.resp_p")),
        protocol="tcp",
        domain=row.get("server_name"),
        log_source="ssl",
        pcap_reference=pcap_reference
    )
