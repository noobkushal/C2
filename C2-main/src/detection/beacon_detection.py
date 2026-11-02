import statistics
import pandas as pd
from typing import Any
from src.utils.config_loader import load_detection_rules
from src.utils.time_utils import iso8601_to_epoch

def calculate_group_beacon_stats(timestamps_iso: list[str]) -> dict[str, Any]:
    """
    Calculates beacon timing statistics for a sorted list of ISO 8601 timestamps.
    Handles edge cases (n<2, 0 duration intervals, duplicate timestamps).
    """
    n_conns = len(timestamps_iso)
    if n_conns == 0:
        return {"connection_count": 0, "intervals": [], "mean": 0.0, "median": 0.0, "stdev": 0.0, "cv": None}
    if n_conns == 1:
        return {"connection_count": 1, "intervals": [], "mean": 0.0, "median": 0.0, "stdev": 0.0, "cv": None}

    # Convert to epoch floats and sort
    epochs = sorted([iso8601_to_epoch(ts) for ts in timestamps_iso])
    intervals = [epochs[i] - epochs[i - 1] for i in range(1, len(epochs))]

    if len(intervals) == 0:
        return {"connection_count": n_conns, "intervals": [], "mean": 0.0, "median": 0.0, "stdev": 0.0, "cv": None}

    mean_val = statistics.mean(intervals)
    median_val = statistics.median(intervals)
    stdev_val = statistics.pstdev(intervals) if len(intervals) >= 2 else 0.0
    cv_val = (stdev_val / mean_val) if mean_val > 0 else 0.0

    return {
        "connection_count": n_conns,
        "intervals": intervals,
        "mean": mean_val,
        "median": median_val,
        "stdev": stdev_val,
        "cv": cv_val,
        "first_seen": timestamps_iso[0],
        "last_seen": timestamps_iso[-1],
    }

def detect_beaconing(
    events_df: pd.DataFrame,
    rules_cfg: dict | None = None,
    rare_destinations: set[str] | None = None
) -> list[dict[str, Any]]:
    """
    Groups events by (source_ip, destination_ip, destination_port) and analyzes
    for C2 beaconing behavior. Returns list of candidate beacon signals.
    """
    if events_df.empty:
        return []

    if rules_cfg is None:
        rules_cfg = load_detection_rules()

    beacon_cfg = rules_cfg.get("beacon", {})
    min_conns = beacon_cfg.get("min_connections", 4)
    max_cv = beacon_cfg.get("max_cv", 0.15)
    high_freq_thresh = beacon_cfg.get("high_frequency_threshold", 60)
    common_ports = rules_cfg.get("common_ports", [80, 443, 53, 22, 25, 110, 143, 993, 995, 3389])

    if rare_destinations is None:
        rare_destinations = set()

    candidates = []

    # Group by (source_ip, destination_ip, destination_port)
    grouped = events_df.groupby(["source_ip", "destination_ip", "destination_port"], dropna=False)

    for (src_ip, dst_ip, dst_port), group in grouped:
        conn_count = len(group)
        if conn_count < min_conns:
            continue

        timestamps = group["timestamp"].tolist()
        stats = calculate_group_beacon_stats(timestamps)

        cv = stats["cv"]
        if cv is None:
            continue

        # Duration in hours
        total_duration_sec = iso8601_to_epoch(stats["last_seen"]) - iso8601_to_epoch(stats["first_seen"])
        duration_hours = max(total_duration_sec / 3600.0, 1.0 / 3600.0)
        conns_per_hour = conn_count / duration_hours

        # Compute signal points per spec §7.3
        signals = []
        raw_score = 0

        # Repeated connections (+30)
        signals.append({"name": "repeated_connections", "points": 30, "detail": f"{conn_count} connections observed"})
        raw_score += 30

        # Low interval variation (+25)
        is_low_cv = (cv <= max_cv)
        if is_low_cv:
            signals.append({"name": "low_interval_variation", "points": 25, "detail": f"CV={cv:.4f} <= max_cv ({max_cv})"})
            raw_score += 25
        else:
            signals.append({"name": "interval_variation", "points": 0, "detail": f"CV={cv:.4f} > max_cv ({max_cv})"})

        # Fixed destination (+20)
        signals.append({"name": "fixed_destination", "points": 20, "detail": f"Fixed destination {dst_ip}:{dst_port}"})
        raw_score += 20

        # Rare destination (+10)
        if dst_ip in rare_destinations:
            signals.append({"name": "rare_destination", "points": 10, "detail": f"{dst_ip} is rarely contacted across hosts"})
            raw_score += 10

        # Unusual port (+10)
        dst_port_int = int(dst_port) if dst_port is not None else 0
        if dst_port_int not in common_ports:
            signals.append({"name": "unusual_port", "points": 10, "detail": f"Destination port {dst_port_int} not in common ports"})
            raw_score += 10

        # High frequency (+5)
        if conns_per_hour >= high_freq_thresh:
            signals.append({"name": "high_frequency", "points": 5, "detail": f"{conns_per_hour:.1f} conns/hr >= {high_freq_thresh}"})
            raw_score += 5

        clamped_score = min(raw_score, 100)

        # Event IDs involved
        event_ids = group["event_id"].tolist() if "event_id" in group.columns else []

        candidate = {
            "source_ip": str(src_ip),
            "destination_ip": str(dst_ip),
            "destination_port": dst_port_int,
            "connection_count": conn_count,
            "mean_interval": stats["mean"],
            "median_interval": stats["median"],
            "stdev_interval": stats["stdev"],
            "cv": cv,
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"],
            "conns_per_hour": conns_per_hour,
            "signals": signals,
            "beacon_score": clamped_score,
            "event_ids": event_ids,
        }
        candidates.append(candidate)

    return candidates
