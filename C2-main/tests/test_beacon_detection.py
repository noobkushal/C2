import pytest
import pandas as pd
from datetime import datetime, timedelta, timezone
from src.detection.beacon_detection import calculate_group_beacon_stats, detect_beaconing

def test_beacon_stats_0_1_2_connections():
    # 0 connections
    res0 = calculate_group_beacon_stats([])
    assert res0["connection_count"] == 0
    assert res0["cv"] is None

    # 1 connection
    res1 = calculate_group_beacon_stats(["2024-03-31T10:00:00Z"])
    assert res1["connection_count"] == 1
    assert res1["cv"] is None

    # 2 connections
    res2 = calculate_group_beacon_stats(["2024-03-31T10:00:00Z", "2024-03-31T10:00:30Z"])
    assert res2["connection_count"] == 2
    assert res2["mean"] == 30.0
    assert res2["stdev"] == 0.0
    assert res2["cv"] == 0.0

def test_perfectly_regular_intervals():
    base = datetime(2024, 3, 31, 12, 0, 0, tzinfo=timezone.utc)
    ts_list = [(base + timedelta(seconds=30 * i)).strftime("%Y-%m-%dT%H:%M:%SZ") for i in range(10)]
    
    stats = calculate_group_beacon_stats(ts_list)
    assert stats["connection_count"] == 10
    assert stats["mean"] == 30.0
    assert stats["stdev"] == 0.0
    assert stats["cv"] == 0.0

def test_highly_irregular_intervals():
    ts_list = [
        "2024-03-31T12:00:00Z",
        "2024-03-31T12:00:10Z",
        "2024-03-31T12:05:00Z",
        "2024-03-31T12:40:00Z",
    ]
    stats = calculate_group_beacon_stats(ts_list)
    assert stats["connection_count"] == 4
    assert stats["cv"] > 0.5

def test_duplicate_timestamps_zero_duration():
    ts_list = [
        "2024-03-31T12:00:00Z",
        "2024-03-31T12:00:00Z",
        "2024-03-31T12:00:00Z",
        "2024-03-31T12:00:00Z",
    ]
    stats = calculate_group_beacon_stats(ts_list)
    assert stats["connection_count"] == 4
    assert stats["mean"] == 0.0
    assert stats["stdev"] == 0.0
    assert stats["cv"] == 0.0

def test_very_large_intervals_days():
    ts_list = [
        "2024-01-01T00:00:00Z",
        "2024-01-10T00:00:00Z",
        "2024-01-19T00:00:00Z",
        "2024-01-28T00:00:00Z",
    ]
    stats = calculate_group_beacon_stats(ts_list)
    assert stats["connection_count"] == 4
    assert stats["mean"] == 9 * 86400.0
    assert stats["stdev"] == 0.0

def test_detect_beaconing_dataframe():
    base = datetime(2024, 3, 31, 12, 0, 0, tzinfo=timezone.utc)
    rows = []
    for i in range(10):
        ts = (base + timedelta(seconds=30 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append({
            "event_id": f"evt-{i}",
            "timestamp": ts,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.50",
            "destination_port": 8443,
            "protocol": "tcp"
        })
    df = pd.DataFrame(rows)

    candidates = detect_beaconing(df, rare_destinations={"10.0.0.50"})
    assert len(candidates) == 1
    c = candidates[0]
    assert c["source_ip"] == "192.168.1.100"
    assert c["destination_ip"] == "10.0.0.50"
    assert c["destination_port"] == 8443
    assert c["cv"] == 0.0
    # Check score components: repeated(30) + low_cv(25) + fixed_dst(20) + rare_dst(10) + unusual_port(10) = 95
    assert c["beacon_score"] >= 80
