import pytest
import pandas as pd
from src.detection.rare_destination import compute_destination_frequency, flag_rare_destinations

def test_rare_destinations_empty():
    df = pd.DataFrame()
    freq = compute_destination_frequency(df)
    assert freq == {}
    rare = flag_rare_destinations(freq)
    assert rare == set()

def test_rare_destinations_single_and_even():
    # 10 sources, 1 contacts 10.0.0.99, all 10 contact 8.8.8.8
    rows = []
    for i in range(10):
        rows.append({"source_ip": f"192.168.1.{i+1}", "destination_ip": "8.8.8.8"})
    rows.append({"source_ip": "192.168.1.1", "destination_ip": "10.0.0.99"})

    df = pd.DataFrame(rows)
    freq = compute_destination_frequency(df)
    assert freq["8.8.8.8"] == 1.0
    assert freq["10.0.0.99"] == 0.1

    rare = flag_rare_destinations(freq, threshold_pct=0.15, max_abs_count=5, events_df=df)
    assert "10.0.0.99" in rare
    assert "8.8.8.8" not in rare
