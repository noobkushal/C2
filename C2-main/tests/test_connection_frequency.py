import pytest
import pandas as pd
from src.detection.connection_frequency import (
    connections_per_minute,
    connections_per_destination,
    connections_per_source,
    flag_high_frequency
)

def test_connection_frequency_empty():
    df = pd.DataFrame()
    s = connections_per_minute(df)
    assert s.empty
    assert connections_per_destination(df) == {}
    assert connections_per_source(df) == {}
    assert flag_high_frequency(df) == []

def test_connection_frequency_threshold():
    rows = []
    # 15 connections within same minute
    for i in range(15):
        rows.append({
            "event_id": f"evt-{i}",
            "timestamp": f"2024-03-31T10:00:{i:02d}Z",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "destination_port": 80
        })
    df = pd.DataFrame(rows)
    high_freq = flag_high_frequency(df, threshold_per_min=10)
    assert len(high_freq) == 1
    assert high_freq[0]["max_connections_per_min"] == 15
