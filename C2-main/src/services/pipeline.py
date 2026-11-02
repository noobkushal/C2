import os
import glob
import pandas as pd
from typing import Any
from src.database.database import init_db
from src.database.repositories import (
    insert_network_events_batch,
    insert_dns_events_batch,
    get_network_events,
    get_dns_events
)
from src.ingestion.zeek_parser import (
    parse_zeek_log,
    map_conn_row,
    map_dns_row,
    map_http_row,
    map_ssl_row
)
from src.detection.rare_destination import compute_destination_frequency, flag_rare_destinations
from src.detection.beacon_detection import detect_beaconing
from src.detection.dns_detection import detect_dns_anomalies
from src.detection.connection_frequency import flag_high_frequency
from src.detection.suspicious_port import check_suspicious_port
from src.detection.correlation import correlate_signals
from src.services.alert_service import create_or_update_alert
from src.utils.config_loader import load_detection_rules
from src.utils.logging_config import logger

def run_detection_on_events(events_df: pd.DataFrame, dns_df: pd.DataFrame, db_path: str | None = None) -> int:
    """
    Runs behavioral detectors against normalized events DataFrames,
    correlates signals, and saves alerts to SQLite database.
    Returns count of alerts created/updated.
    """
    if events_df.empty and dns_df.empty:
        logger.info("No events available to run detection on.")
        return 0

    rules_cfg = load_detection_rules()

    # 1. Rare destination analysis
    dest_freq = compute_destination_frequency(events_df)
    rare_dest_cfg = rules_cfg.get("rare_destination", {})
    rare_destinations = flag_rare_destinations(
        dest_freq,
        threshold_pct=rare_dest_cfg.get("max_occurrence_pct", 0.05),
        max_abs_count=rare_dest_cfg.get("max_absolute_count", 10),
        events_df=events_df
    )

    # 2. Detector executions
    beacon_candidates = detect_beaconing(events_df, rules_cfg=rules_cfg, rare_destinations=rare_destinations)
    dns_anomalies = detect_dns_anomalies(dns_df, rules_cfg=rules_cfg)
    high_freq_signals = flag_high_frequency(
        events_df,
        threshold_per_min=rules_cfg.get("connection_frequency", {}).get("threshold_per_minute", 10)
    )

    # Index candidates by (src, dst, port)
    beacon_map = {(c["source_ip"], c["destination_ip"], c["destination_port"]): c for c in beacon_candidates}
    high_freq_map = {(h["source_ip"], h["destination_ip"], h["destination_port"]): h for h in high_freq_signals}

    dns_map = {}
    for da in dns_anomalies:
        dns_map.setdefault(da["source_ip"], []).append(da)

    # Collect all unique candidate tuples
    candidate_tuples = set(beacon_map.keys()).union(set(high_freq_map.keys()))

    if not events_df.empty:
        for (src_ip, dst_ip, dst_port), _ in events_df.groupby(["source_ip", "destination_ip", "destination_port"], dropna=False):
            dst_port_int = int(dst_port) if dst_port is not None and not pd.isna(dst_port) else None
            candidate_tuples.add((str(src_ip), str(dst_ip), dst_port_int))

    for src_ip in dns_map.keys():
        candidate_tuples.add((src_ip, "DNS_SERVER", 53))

    alerts_saved = 0

    for (src_ip, dst_ip, dst_port) in candidate_tuples:
        beacon_cand = beacon_map.get((src_ip, dst_ip, dst_port))
        dns_anoms = dns_map.get(src_ip)
        high_freq_sig = high_freq_map.get((src_ip, dst_ip, dst_port))

        rare_sig = None
        if dst_ip in rare_destinations:
            rare_sig = {"destination_ip": dst_ip}

        port_sig = check_suspicious_port(dst_port, rules_cfg=rules_cfg)

        alert_obj = correlate_signals(
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=dst_port,
            beacon_candidate=beacon_cand,
            dns_anomalies=dns_anoms,
            rare_dest_signal=rare_sig,
            high_freq_signal=high_freq_sig,
            port_signal=port_sig,
            rules_cfg=rules_cfg
        )

        if alert_obj:
            create_or_update_alert(alert_obj, db_path=db_path)
            alerts_saved += 1

    logger.info(f"Detection engine completed. {alerts_saved} alerts generated/updated.")
    return alerts_saved

def run_pipeline_on_zeek_dir(zeek_dir: str, pcap_ref: str | None = None, db_path: str | None = None) -> dict[str, int]:
    """
    Parses Zeek log files in zeek_dir, normalizes events, writes to SQLite,
    and runs detection engine end-to-end.
    """
    init_db(db_path)
    logger.info(f"Starting ETL pipeline on Zeek directory: {zeek_dir}")

    conn_events = []
    dns_events = []
    http_events = []
    ssl_events = []

    # Find log files
    for log_path in glob.glob(os.path.join(zeek_dir, "*.log")):
        base = os.path.basename(log_path)
        if base.startswith("conn"):
            for row in parse_zeek_log(log_path):
                e = map_conn_row(row, pcap_reference=pcap_ref)
                if e:
                    conn_events.append(e)
        elif base.startswith("dns"):
            for row in parse_zeek_log(log_path):
                e = map_dns_row(row)
                if e:
                    dns_events.append(e)
        elif base.startswith("http"):
            for row in parse_zeek_log(log_path):
                e = map_http_row(row, pcap_reference=pcap_ref)
                if e:
                    http_events.append(e)
        elif base.startswith("ssl"):
            for row in parse_zeek_log(log_path):
                e = map_ssl_row(row, pcap_reference=pcap_ref)
                if e:
                    ssl_events.append(e)

    all_net_events = conn_events + http_events + ssl_events
    inserted_net = insert_network_events_batch(all_net_events, db_path=db_path)
    inserted_dns = insert_dns_events_batch(dns_events, db_path=db_path)

    # Fetch stored events for detection
    events_df = get_network_events(limit=50000, db_path=db_path)
    dns_df = get_dns_events(limit=50000, db_path=db_path)

    alerts_count = run_detection_on_events(events_df, dns_df, db_path=db_path)

    return {
        "network_events_parsed": len(all_net_events),
        "network_events_inserted": inserted_net,
        "dns_events_parsed": len(dns_events),
        "dns_events_inserted": inserted_dns,
        "alerts_generated": alerts_count
    }

def run_detection_only(db_path: str | None = None) -> int:
    """Runs detection engine on all records currently in SQLite database."""
    init_db(db_path)
    events_df = get_network_events(limit=50000, db_path=db_path)
    dns_df = get_dns_events(limit=50000, db_path=db_path)
    return run_detection_on_events(events_df, dns_df, db_path=db_path)
