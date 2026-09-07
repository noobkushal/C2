from datetime import datetime, timezone
import dateutil.parser

def epoch_to_iso8601(epoch: float | int | str) -> str:
    """Converts a unix epoch float/int timestamp to ISO 8601 UTC string."""
    try:
        ts = float(epoch)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f"Invalid timestamp format: {epoch}")

def parse_iso8601(iso_str: str) -> datetime:
    """Parses an ISO 8601 string to timezone-aware UTC datetime."""
    dt = dateutil.parser.parse(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt

def iso8601_to_epoch(iso_str: str) -> float:
    """Converts ISO 8601 string to Unix epoch float seconds."""
    dt = parse_iso8601(iso_str)
    return dt.timestamp()

def current_iso8601() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
