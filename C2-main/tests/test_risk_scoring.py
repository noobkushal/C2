import pytest
from src.detection.risk_scoring import compute_score, severity_for_score, compute_confidence

def test_risk_score_no_signals():
    assert compute_score([]) == 0
    assert severity_for_score(0) == "LOW"

def test_risk_score_clamped_100():
    signals = [{"points": 50}, {"points": 40}, {"points": 30}]
    score = compute_score(signals)
    assert score == 100
    assert severity_for_score(score) == "CRITICAL"

def test_severity_boundaries():
    assert severity_for_score(0) == "LOW"
    assert severity_for_score(29) == "LOW"
    assert severity_for_score(30) == "MEDIUM"
    assert severity_for_score(59) == "MEDIUM"
    assert severity_for_score(60) == "HIGH"
    assert severity_for_score(79) == "HIGH"
    assert severity_for_score(80) == "CRITICAL"
    assert severity_for_score(100) == "CRITICAL"

def test_confidence_derivation():
    assert compute_confidence(0) == 0.0
    assert compute_confidence(1) == 0.40
    assert compute_confidence(2) == 0.65
    assert compute_confidence(3) == 0.85
    assert compute_confidence(5) == 0.91
    assert compute_confidence(10) == 0.95
