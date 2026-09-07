from typing import Any
from src.utils.config_loader import load_detection_rules

DEFAULT_SEVERITY_BANDS = [
    {"min": 0, "max": 29, "name": "LOW"},
    {"min": 30, "max": 59, "name": "MEDIUM"},
    {"min": 60, "max": 79, "name": "HIGH"},
    {"min": 80, "max": 100, "name": "CRITICAL"},
]

def compute_score(signals: list[dict[str, Any]] | dict[str, Any]) -> int:
    """
    Computes total risk score by summing point values from signal dicts or map,
    clamped to range [0, 100].
    """
    raw_sum = 0
    if isinstance(signals, list):
        for sig in signals:
            pts = sig.get("points") or sig.get("contributes_points") or 0
            raw_sum += int(pts)
    elif isinstance(signals, dict):
        for k, v in signals.items():
            if isinstance(v, (int, float)):
                raw_sum += int(v)
            elif isinstance(v, bool) and v:
                raw_sum += 10

    return max(0, min(100, raw_sum))

def severity_for_score(score: int, bands: list[dict[str, Any]] | None = None) -> str:
    """
    Maps a risk score (0-100) to a severity band name (LOW, MEDIUM, HIGH, CRITICAL).
    Uses bands from config/detection_rules.yaml if present.
    """
    if bands is None:
        rules_cfg = load_detection_rules()
        bands = rules_cfg.get("severity_bands", DEFAULT_SEVERITY_BANDS)

    clamped_score = max(0, min(100, score))
    for b in bands:
        if b["min"] <= clamped_score <= b["max"]:
            return str(b["name"]).upper()

    if clamped_score >= 80:
        return "CRITICAL"
    elif clamped_score >= 60:
        return "HIGH"
    elif clamped_score >= 30:
        return "MEDIUM"
    return "LOW"

def compute_confidence(detector_count: int) -> float:
    """
    Derives confidence score (0.0 to 0.95) based on independent detector agreement count.
    Never returns 1.0 certainty from behavioral heuristics alone.
    """
    if detector_count <= 0:
        return 0.0
    elif detector_count == 1:
        return 0.40
    elif detector_count == 2:
        return 0.65
    elif detector_count == 3:
        return 0.85
    else:
        return round(min(0.95, 0.85 + (detector_count - 3) * 0.03), 2)
