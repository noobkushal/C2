import pandas as pd
from typing import Any

def compute_destination_frequency(events_df: pd.DataFrame) -> dict[str, float]:
    """
    Computes the fraction of unique sources that contacted each destination IP.
    """
    if events_df.empty:
        return {}

    total_sources = events_df["source_ip"].nunique()
    if total_sources == 0:
        return {}

    dst_sources = events_df.groupby("destination_ip")["source_ip"].nunique().to_dict()
    return {dst: count / float(total_sources) for dst, count in dst_sources.items()}

def flag_rare_destinations(
    freq_table: dict[str, float],
    threshold_pct: float = 0.05,
    max_abs_count: int = 10,
    events_df: pd.DataFrame | None = None
) -> set[str]:
    """
    Flags destinations contacted by <= threshold_pct of total unique sources AND
    total connection count <= max_abs_count.
    """
    if not freq_table:
        return set()

    dst_counts = {}
    if events_df is not None and not events_df.empty:
        dst_counts = events_df.groupby("destination_ip").size().to_dict()

    rare_dsts = set()
    for dst, frac in freq_table.items():
        if frac <= threshold_pct:
            cnt = dst_counts.get(dst, 1)
            if cnt <= max_abs_count:
                rare_dsts.add(dst)

    return rare_dsts
