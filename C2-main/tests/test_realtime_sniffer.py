import tempfile
import os
import pytest
from src.database.database import init_db
from src.services.admin_permission_service import (
    get_admin_permission_status,
    grant_admin_permission,
    revoke_admin_permission
)
from src.ingestion.realtime_sniffer import RealTimeSnifferEngine

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

def test_admin_permission_governance(temp_db):
    status = get_admin_permission_status(db_path=temp_db)
    assert status["is_granted"] is False

    # Grant permission
    assert grant_admin_permission("Admin_Test", db_path=temp_db) is True
    status_granted = get_admin_permission_status(db_path=temp_db)
    assert status_granted["is_granted"] is True
    assert status_granted["granted_by"] == "Admin_Test"

    # Revoke permission
    assert revoke_admin_permission("Admin_Test", db_path=temp_db) is True
    status_revoked = get_admin_permission_status(db_path=temp_db)
    assert status_revoked["is_granted"] is False

def test_sniffer_permission_enforcement(temp_db):
    sniffer = RealTimeSnifferEngine()
    
    # Starting without permission must raise PermissionError
    with pytest.raises(PermissionError):
        sniffer.start_sniffing(db_path=temp_db)

    # Grant permission and verify sniffer can start
    grant_admin_permission("Admin_Test", db_path=temp_db)
    assert sniffer.start_sniffing(db_path=temp_db) is True
    assert sniffer.is_running() is True
    
    sniffer.stop_sniffing()
    revoke_admin_permission("Admin_Test", db_path=temp_db)
