import tempfile
import os
import pytest
from src.database.database import init_db
from src.services.auth_service import (
    authenticate_user,
    create_session,
    verify_session,
    has_role
)

@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    init_db(db_path)
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

def test_default_account_authentication(temp_db):
    # Admin login
    admin_user = authenticate_user("admin", "Admin@123", db_path=temp_db)
    assert admin_user is not None
    assert admin_user["username"] == "admin"
    assert admin_user["role"] == "ADMIN"
    assert has_role(admin_user, "ADMIN") is True
    assert has_role(admin_user, "ANALYST") is True  # Admin has all permissions

    # Analyst login
    analyst_user = authenticate_user("analyst", "Analyst@123", db_path=temp_db)
    assert analyst_user is not None
    assert analyst_user["username"] == "analyst"
    assert analyst_user["role"] == "ANALYST"
    assert has_role(analyst_user, "ANALYST") is True
    assert has_role(analyst_user, "ADMIN") is False

def test_invalid_login(temp_db):
    assert authenticate_user("admin", "WrongPassword", db_path=temp_db) is None
    assert authenticate_user("nonexistent", "Admin@123", db_path=temp_db) is None

def test_session_lifecycle(temp_db):
    user = authenticate_user("admin", "Admin@123", db_path=temp_db)
    assert user is not None
    
    token = create_session(user["user_id"], db_path=temp_db)
    assert token is not None
    
    verified = verify_session(token, db_path=temp_db)
    assert verified is not None
    assert verified["username"] == "admin"
    assert verified["role"] == "ADMIN"
