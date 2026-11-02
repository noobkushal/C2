import pytest
import pandas as pd
from src.detection.dns_detection import detect_dns_anomalies

def test_dns_anomalies_empty():
    df = pd.DataFrame()
    res = detect_dns_anomalies(df)
    assert res == []

def test_dns_long_domain():
    long_domain = "a" * 60 + ".example.com"
    df = pd.DataFrame([{
        "event_id": "dns-1",
        "timestamp": "2024-03-31T10:00:00Z",
        "source_ip": "192.168.1.5",
        "domain": long_domain
    }])
    res = detect_dns_anomalies(df)
    assert len(res) >= 1
    anom = res[0]
    sig_names = [s["indicator_name"] for s in anom["signals"]]
    assert "long_domain" in sig_names

def test_dns_high_frequency_and_rare():
    df_rows = []
    for i in range(25):
        df_rows.append({
            "event_id": f"dns-{i}",
            "timestamp": f"2024-03-31T10:{i:02d}:00Z",
            "source_ip": "192.168.1.10",
            "domain": "rare-tunnel.test.org"
        })
    df = pd.DataFrame(df_rows)
    rules = {
        "dns": {
            "long_domain_length": 50,
            "high_frequency_threshold": 20,
            "rare_domain_max_count": 30,
            "max_unique_subdomains": 5
        }
    }
    res = detect_dns_anomalies(df, rules_cfg=rules)
    assert len(res) >= 1
    sig_names = [s["indicator_name"] for s in res[0]["signals"]]
    assert "high_frequency_domain" in sig_names
    assert "rare_domain" in sig_names

def test_dns_excessive_subdomains():
    df_rows = []
    for i in range(8):
        df_rows.append({
            "event_id": f"sub-{i}",
            "timestamp": f"2024-03-31T11:{i:02d}:00Z",
            "source_ip": "192.168.1.20",
            "domain": f"subdomain{i}.tunnelbase.com"
        })
    df = pd.DataFrame(df_rows)
    res = detect_dns_anomalies(df)
    sig_names = []
    for r in res:
        for s in r["signals"]:
            sig_names.append(s["indicator_name"])
    assert "excessive_subdomains" in sig_names
