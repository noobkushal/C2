import json
from typing import Any
from src.database.models import Alert
from src.detection.risk_scoring import compute_score, severity_for_score, compute_confidence
from src.utils.time_utils import current_iso8601

def correlate_signals(
    source_ip: str,
    destination_ip: str,
    destination_port: int | None,
    beacon_candidate: dict[str, Any] | None = None,
    dns_anomalies: list[dict[str, Any]] | None = None,
    rare_dest_signal: dict[str, Any] | None = None,
    high_freq_signal: dict[str, Any] | None = None,
    port_signal: dict[str, Any] | None = None,
    rules_cfg: dict | None = None
) -> Alert | None:
    """
    Consolidates multiple detector signals for a (source_ip, destination_ip, destination_port)
    into a single unified Alert object with evidence JSON.
    """
    signals: list[dict[str, Any]] = []
    reasons: list[str] = []
    detectors_fired = set()
    event_ids = set()

    first_seen = "9999-12-31T23:59:59Z"
    last_seen = "1970-01-01T00:00:00Z"

    # 1. Beaconing signal
    if beacon_candidate:
        detectors_fired.add("beacon_detection")
        cv = beacon_candidate["cv"]
        conn_cnt = beacon_candidate["connection_count"]
        first_seen = min(first_seen, beacon_candidate["first_seen"])
        last_seen = max(last_seen, beacon_candidate["last_seen"])
        event_ids.update(beacon_candidate.get("event_ids", []))

        reasons.append(f"Regular-interval connections (CV={cv:.4f}) with {conn_cnt} connections")
        for s in beacon_candidate.get("signals", []):
            if s.get("points", 0) > 0:
                signals.append(s)

    # 2. DNS anomalies
    if dns_anomalies:
        detectors_fired.add("dns_detection")
        for da in dns_anomalies:
            first_seen = min(first_seen, da.get("first_seen", first_seen))
            last_seen = max(last_seen, da.get("last_seen", last_seen))
            event_ids.update(da.get("event_ids", []))
            for s in da.get("signals", []):
                signals.append({"name": f"dns_{s['indicator_name']}", "points": s["contributes_points"], "detail": s["detail"]})
                reasons.append(s["detail"])

    # 3. Rare Destination
    if rare_dest_signal:
        detectors_fired.add("rare_destination")
        signals.append({"name": "rare_destination", "points": 10, "detail": f"Rarely contacted destination {destination_ip}"})
        reasons.append(f"Rare destination {destination_ip}")

    # 4. High Frequency
    if high_freq_signal:
        detectors_fired.add("connection_frequency")
        first_seen = min(first_seen, high_freq_signal.get("first_seen", first_seen))
        last_seen = max(last_seen, high_freq_signal.get("last_seen", last_seen))
        event_ids.update(high_freq_signal.get("event_ids", []))
        max_rate = high_freq_signal.get("max_connections_per_min", 0)
        signals.append({"name": "high_frequency", "points": 10, "detail": f"Burst rate of {max_rate} conns/min"})
        reasons.append(f"High connection frequency ({max_rate} conns/min)")

    # 5. Suspicious/Unusual Port
    if port_signal:
        detectors_fired.add("suspicious_port")
        signals.append({"name": "unusual_port_observed", "points": port_signal["contributes_points"], "detail": port_signal["detail"]})
        reasons.append(port_signal["detail"])

    if not detectors_fired:
        return None

    # Default timestamps if not set
    now = current_iso8601()
    if first_seen == "9999-12-31T23:59:59Z":
        first_seen = now
    if last_seen == "1970-01-01T00:00:00Z":
        last_seen = now

    # Alert type classification
    if "beacon_detection" in detectors_fired:
        primary_alert_type = "BEACONING"
    elif "dns_detection" in detectors_fired:
        primary_alert_type = "DNS_ANOMALY"
    elif "rare_destination" in detectors_fired:
        primary_alert_type = "RARE_DESTINATION"
    elif "connection_frequency" in detectors_fired:
        primary_alert_type = "HIGH_FREQUENCY"
    else:
        primary_alert_type = "SUSPICIOUS_PORT"

    total_risk = compute_score(signals)
    severity = severity_for_score(total_risk, bands=rules_cfg.get("severity_bands") if rules_cfg else None)
    confidence = compute_confidence(len(detectors_fired))
    joined_reason = "; ".join(reasons)

    evidence_blob = {
        "detectors_fired": list(detectors_fired),
        "detector_count": len(detectors_fired),
        "signals": signals,
        "event_ids": list(event_ids),
        "raw_reasons": reasons
    }

    return Alert(
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        alert_type=primary_alert_type,
        severity=severity,
        confidence=confidence,
        risk_score=total_risk,
        reason=joined_reason,
        evidence=json.dumps(evidence_blob),
        status="NEW",
        first_seen=first_seen,
        last_seen=last_seen
    )
