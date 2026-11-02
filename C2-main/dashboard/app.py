import streamlit as st
import os
import sys

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.database import init_db
from src.services.auth_service import verify_session
from dashboard.theme import apply_soc_theme

st.set_page_config(
    page_title="NetWatch SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database schema
init_db()

# Apply Stitch enterprise SOC dark theme
apply_soc_theme()

# Session State Initialization
if "session_token" not in st.session_state:
    st.session_state["session_token"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Overview"
if "selected_alert_id" not in st.session_state:
    st.session_state["selected_alert_id"] = None

current_user = verify_session(st.session_state["session_token"]) if st.session_state["session_token"] else None

st.sidebar.title("🛡️ NetWatch SOC")
st.sidebar.caption("Network Traffic & C2 Detection Lab")

if current_user:
    role_color = "red" if current_user['role'] == "ADMIN" else "blue"
    st.sidebar.markdown(f"👤 User: **{current_user['username']}** (:{role_color}[{current_user['role']}])")
else:
    st.sidebar.warning("🔒 Not Logged In — Access Restricted")

pages = {
    "Login / Auth": "dashboard/pages/login.py",
    "Overview": "dashboard/pages/overview.py",
    "Real-Time Monitor": "dashboard/pages/realtime_monitor.py",
    "Network Traffic": "dashboard/pages/network_traffic.py",
    "Alerts": "dashboard/pages/alerts.py",
    "Investigation": "dashboard/pages/investigation.py",
    "C2 Detection": "dashboard/pages/c2_detection.py",
    "DNS Analysis": "dashboard/pages/dns_analysis.py",
    "Connections": "dashboard/pages/connections.py",
    "Evidence": "dashboard/pages/evidence.py",
    "Detection Rules": "dashboard/pages/detection_rules.py",
    "Reports": "dashboard/pages/reports.py",
    "Settings": "dashboard/pages/settings.py",
}

selected_page = st.sidebar.radio(
    "Navigation",
    list(pages.keys()),
    index=list(pages.keys()).index(st.session_state["current_page"]) if st.session_state["current_page"] in pages else 0
)

if selected_page != st.session_state["current_page"]:
    st.session_state["current_page"] = selected_page

st.sidebar.divider()
st.sidebar.info("Operational Status: ONLINE\nMode: Real-World NIC & Telemetry Lab")

# Load selected page script dynamically
page_file = pages[st.session_state["current_page"]]
try:
    with open(page_file, "r", encoding="utf-8") as f:
        code = compile(f.read(), page_file, "exec")
        exec(code, globals())
except Exception as e:
    st.error(f"Error loading page '{st.session_state['current_page']}': {e}")
