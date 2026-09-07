import tempfile
import os
import pytest
from src.database.database import init_db
from src.database.models import NetworkEvent, DNSEvent, Alert, Investigation, DetectionRule
from src.database.repositories import (
    insert_network_event,
    insert_network_events_batch,
    get_network_events,
    get_network_events_count,
    insert_dns_events_batch,
    get_dns_events,
    upsert_alert,
    get_alerts,
    get_alert_by_id,
    update_alert_status,
    upsert_investigation,
    get_investigation_by_alert_id,
    get_detection_rules,
    update_detection_rule,
    get_overview_kpis
)

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

def test_empty_database_queries(temp_db):
    df_net = get_network_events(db_path=temp_db)
    assert df_net.empty
    assert get_network_events_count(db_path=temp_db) == 0

    df_dns = get_dns_events(db_path=temp_db)
    assert df_dns.empty

    df_alerts = get_alerts(db_path=temp_db)
    assert df_alerts.empty

    kpis = get_overview_kpis(db_path=temp_db)
    assert kpis["network_events"] == 0
    assert kpis["active_alerts"] == 0

def test_network_events_round_trip_and_duplicates(temp_db):
    evt1 = NetworkEvent(
        event_id="evt-001",
        timestamp="2024-03-31T10:00:00Z",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        log_source="conn"
    )
    assert insert_network_event(evt1, db_path=temp_db) is True

    # Duplicate insert
    assert insert_network_event(evt1, db_path=temp_db) is True

    df = get_network_events(db_path=temp_db)
    assert len(df) == 1
    assert df.iloc[0]["event_id"] == "evt-001"

def test_alerts_upsert_and_investigation_notes(temp_db):
    alert1 = Alert(
        alert_id="alt-001",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.1",
        destination_port=8443,
        alert_type="BEACONING",
        severity="HIGH",
        confidence=0.85,
        risk_score=75,
        reason="Beaconing detected",
        first_seen="2024-03-31T10:00:00Z",
        last_seen="2024-03-31T10:10:00Z"
    )
    aid = upsert_alert(alert1, db_path=temp_db)
    assert aid == "alt-001"

    # Upsert updates last_seen/score
    alert1.last_seen = "2024-03-31T10:20:00Z"
    alert1.risk_score = 90
    upsert_alert(alert1, db_path=temp_db)

    retrieved = get_alert_by_id("alt-001", db_path=temp_db)
    assert retrieved is not None
    assert retrieved.risk_score == 90
    assert retrieved.last_seen == "2024-03-31T10:20:00Z"

    # Investigation notes
    inv = upsert_investigation("alt-001", verdict="TRUE_POSITIVE", new_note="Confirmed C2 traffic", db_path=temp_db)
    assert inv.verdict == "TRUE_POSITIVE"
    assert "Confirmed C2 traffic" in inv.notes

def test_detection_rules_repository(temp_db):
    rules = get_detection_rules(db_path=temp_db)
    assert len(rules) > 0
    rule_id = rules[0].rule_id

    assert update_detection_rule(rule_id, enabled=0, threshold=99.0, db_path=temp_db) is True
    updated_rules = get_detection_rules(db_path=temp_db)
    updated_map = {r.rule_id: r for r in updated_rules}
    assert updated_map[rule_id].enabled == 0
    assert updated_map[rule_id].threshold == 99.0
