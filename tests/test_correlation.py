import pytest
from src.detection.correlation import correlate_signals

def test_correlate_no_signals():
    alert = correlate_signals("192.168.1.10", "10.0.0.1", 80)
    assert alert is None

def test_correlate_multi_detector_signals():
    beacon_cand = {
        "cv": 0.05,
        "connection_count": 20,
        "first_seen": "2024-03-31T10:00:00Z",
        "last_seen": "2024-03-31T10:10:00Z",
        "signals": [{"name": "repeated_connections", "points": 30}, {"name": "low_cv", "points": 25}],
        "event_ids": ["e1", "e2"]
    }
    rare_sig = {"destination_ip": "10.0.0.1"}
    port_sig = {"contributes_points": 10, "detail": "Unusual port 8443"}

    alert = correlate_signals(
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        destination_port=8443,
        beacon_candidate=beacon_cand,
        rare_dest_signal=rare_sig,
        port_signal=port_sig
    )

    assert alert is not None
    assert alert.alert_type == "BEACONING"
    assert alert.severity in ("HIGH", "CRITICAL")
    assert alert.confidence >= 0.80  # 3 detectors (beacon, rare, port)
    assert "8443" in alert.reason
    assert "10.0.0.1" in alert.reason
