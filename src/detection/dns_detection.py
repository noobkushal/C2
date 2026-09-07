"""
DNS Anomaly Detection Module.

These indicators contribute to investigation risk. They do not, individually or
combined, constitute proof of malicious activity.
"""

import pandas as pd
from typing import Any
from src.utils.config_loader import load_detection_rules

def _extract_base_domain(domain: str) -> str:
    """Extracts simple base domain heuristic (e.g., sub.example.com -> example.com)."""
    parts = domain.strip(".").split(".")
    if len(parts) <= 2:
        return domain.lower()
    return ".".join(parts[-2:]).lower()

def detect_dns_anomalies(
    dns_events_df: pd.DataFrame,
    rules_cfg: dict | None = None
) -> list[dict[str, Any]]:
    """
    Analyzes DNS events for long domains, high frequency domains, rare domains,
    and excessive unique subdomains.
    Returns candidate anomaly dictionaries containing signals and evidence.
    """
    if dns_events_df.empty:
        return []

    if rules_cfg is None:
        rules_cfg = load_detection_rules()

    dns_cfg = rules_cfg.get("dns", {})
    long_len_thresh = dns_cfg.get("long_domain_length", 50)
    high_freq_thresh = dns_cfg.get("high_frequency_threshold", 20)
    rare_max_count = dns_cfg.get("rare_domain_max_count", 2)
    max_subdom_thresh = dns_cfg.get("max_unique_subdomains", 5)

    total_sources = dns_events_df["source_ip"].nunique()
    anomalies = []

    # 1. Long domains check per event/domain
    # 2. High frequency domain per (source_ip, domain)
    # 3. Rare domain per domain across dataset
    # 4. Excessive subdomains per (source_ip, base_domain)

    # Pre-calculate domain occurrence stats
    domain_sources = dns_events_df.groupby("domain")["source_ip"].nunique().to_dict()
    domain_counts = dns_events_df.groupby("domain").size().to_dict()

    # Group by (source_ip, domain) for primary analysis
    grouped = dns_events_df.groupby(["source_ip", "domain"])

    for (src_ip, domain), group in grouped:
        signals = []
        raw_score = 0
        q_count = len(group)

        # Indicator 1: Long Domain
        if len(domain) > long_len_thresh:
            signals.append({
                "indicator_name": "long_domain",
                "value": len(domain),
                "threshold": long_len_thresh,
                "contributes_points": 25,
                "detail": f"Domain length ({len(domain)}) exceeds threshold ({long_len_thresh})"
            })
            raw_score += 25

        # Indicator 2: High Frequency Domain
        if q_count > high_freq_thresh:
            signals.append({
                "indicator_name": "high_frequency_domain",
                "value": q_count,
                "threshold": high_freq_thresh,
                "contributes_points": 25,
                "detail": f"Query count ({q_count}) exceeds threshold ({high_freq_thresh})"
            })
            raw_score += 25

        # Indicator 3: Rare Domain
        n_srcs = domain_sources.get(domain, 0)
        tot_cnt = domain_counts.get(domain, 0)
        if n_srcs == 1 and tot_cnt <= rare_max_count:
            signals.append({
                "indicator_name": "rare_domain",
                "value": f"sources={n_srcs}, count={tot_cnt}",
                "threshold": f"sources=1, max_count={rare_max_count}",
                "contributes_points": 20,
                "detail": f"Domain seen from only 1 source with total count {tot_cnt}"
            })
            raw_score += 20

        if signals:
            timestamps = group["timestamp"].tolist()
            anomalies.append({
                "source_ip": str(src_ip),
                "domain": str(domain),
                "query_count": q_count,
                "signals": signals,
                "risk_score": min(raw_score, 100),
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "event_ids": group["event_id"].tolist() if "event_id" in group.columns else []
            })

    # Indicator 4: Excessive Unique Subdomains under base domain per source
    dns_events_df_copy = dns_events_df.copy()
    dns_events_df_copy["base_domain"] = dns_events_df_copy["domain"].apply(_extract_base_domain)
    subdom_grouped = dns_events_df_copy.groupby(["source_ip", "base_domain"])

    for (src_ip, base_domain), group in subdom_grouped:
        unique_subdomains = group["domain"].nunique()
        if unique_subdomains > max_subdom_thresh:
            timestamps = group["timestamp"].tolist()
            anomalies.append({
                "source_ip": str(src_ip),
                "domain": str(base_domain),
                "query_count": len(group),
                "signals": [{
                    "indicator_name": "excessive_subdomains",
                    "value": unique_subdomains,
                    "threshold": max_subdom_thresh,
                    "contributes_points": 40,
                    "detail": f"Distinct subdomains ({unique_subdomains}) exceed threshold ({max_subdom_thresh}) for base domain {base_domain}"
                }],
                "risk_score": 40,
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "event_ids": group["event_id"].tolist() if "event_id" in group.columns else []
            })

    return anomalies
