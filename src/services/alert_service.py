from src.database.models import Alert, Investigation
from src.database.repositories import (
    upsert_alert,
    get_alert_by_id,
    update_alert_status,
    get_investigation_by_alert_id,
    upsert_investigation
)
from src.utils.logging_config import logger

def create_or_update_alert(alert: Alert, db_path: str | None = None) -> str:
    """Inserts or updates an alert record in SQLite database."""
    alert_id = upsert_alert(alert, db_path=db_path)
    logger.info(f"Alert {alert_id} ({alert.alert_type}, {alert.severity}, score={alert.risk_score}) saved.")
    return alert_id

def get_alert_details(alert_id: str, db_path: str | None = None) -> tuple[Alert | None, Investigation | None]:
    """Retrieves alert record and linked investigation record."""
    alert = get_alert_by_id(alert_id, db_path=db_path)
    if not alert:
        return None, None
    investigation = get_investigation_by_alert_id(alert_id, db_path=db_path)
    return alert, investigation

def update_status(
    alert_id: str,
    new_status: str,
    analyst_note: str | None = None,
    verdict: str | None = None,
    db_path: str | None = None
) -> bool:
    """Updates status for alert and appends timestamped note to investigation record."""
    success = update_alert_status(alert_id, new_status, db_path=db_path)
    if success:
        upsert_investigation(
            alert_id=alert_id,
            verdict=verdict,
            new_note=analyst_note,
            analyst_status=new_status,
            db_path=db_path
        )
        logger.info(f"Alert {alert_id} status updated to {new_status}")
    return success
