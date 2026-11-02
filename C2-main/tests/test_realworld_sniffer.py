import tempfile
import os
import pytest
from src.database.database import init_db
from src.services.auth_service import authenticate_user
from src.services.admin_permission_service import grant_admin_permission, revoke_admin_permission
from src.ingestion.realworld_sniffer import RealWorldSniffer, list_active_interfaces

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

def test_list_interfaces():
    ifaces = list_active_interfaces()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0

def test_realworld_sniffer_auth_enforcement(temp_db):
    sniffer = RealWorldSniffer()
    admin_user = authenticate_user("admin", "Admin@123", db_path=temp_db)
    analyst_user = authenticate_user("analyst", "Analyst@123", db_path=temp_db)

    # 1. Analyst login attempting live sniffing -> PermissionError (Role authorization error)
    grant_admin_permission("admin", db_path=temp_db)
    with pytest.raises(PermissionError):
        sniffer.start_sniffing(user_obj=analyst_user, db_path=temp_db)

    # 2. Revoked consent attempting live sniffing -> PermissionError (Admin consent error)
    revoke_admin_permission("admin", db_path=temp_db)
    with pytest.raises(PermissionError):
        sniffer.start_sniffing(user_obj=admin_user, db_path=temp_db)

    # 3. Admin user + Granted consent -> Starts live sniffing
    grant_admin_permission("admin", db_path=temp_db)
    assert sniffer.start_sniffing(user_obj=admin_user, db_path=temp_db) is True
    assert sniffer.is_running() is True

    sniffer.stop_sniffing()
    revoke_admin_permission("admin", db_path=temp_db)
