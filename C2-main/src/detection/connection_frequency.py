import pandas as pd
from typing import Any

def connections_per_minute(
    events_df: pd.DataFrame,
    source_ip: str | None = None,
    destination_ip: str | None = None
) -> pd.Series:
    """Computes connection counts resampled per minute."""
    if events_df.empty:
        return pd.Series(dtype=int)

    df = events_df.copy()
    if source_ip:
        df = df[df["source_ip"] == source_ip]
    if destination_ip:
        df = df[df["destination_ip"] == destination_ip]

    if df.empty:
        return pd.Series(dtype=int)

    df["dt"] = pd.to_datetime(df["timestamp"])
    df.set_index("dt", inplace=True)
    res = df.resample("1min").size()
    return res

def connections_per_destination(events_df: pd.DataFrame) -> dict[str, int]:
    """Returns dict of destination_ip -> connection count."""
    if events_df.empty:
        return {}
    return events_df.groupby("destination_ip").size().to_dict()

def connections_per_source(events_df: pd.DataFrame) -> dict[str, int]:
    """Returns dict of source_ip -> connection count."""
    if events_df.empty:
        return {}
    return events_df.groupby("source_ip").size().to_dict()

def flag_high_frequency(
    events_df: pd.DataFrame,
    threshold_per_min: float = 10.0
) -> list[dict[str, Any]]:
    """
    Flags (source_ip, destination_ip) pairs where any 1-minute bucket exceeds threshold_per_min.
    """
    if events_df.empty:
        return []

    df = events_df.copy()
    df["dt"] = pd.to_datetime(df["timestamp"])

    high_freq_signals = []
    grouped = df.groupby(["source_ip", "destination_ip", "destination_port"])

    for (src_ip, dst_ip, dst_port), group in grouped:
        res = group.set_index("dt").resample("1min").size()
        max_rate = res.max() if not res.empty else 0
        if max_rate >= threshold_per_min:
            timestamps = group["timestamp"].tolist()
            high_freq_signals.append({
                "source_ip": str(src_ip),
                "destination_ip": str(dst_ip),
                "destination_port": int(dst_port) if dst_port is not None else 0,
                "max_connections_per_min": int(max_rate),
                "threshold": threshold_per_min,
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "event_ids": group["event_id"].tolist() if "event_id" in group.columns else []
            })

    return high_freq_signals
