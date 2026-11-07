import streamlit as st
import os
import sys

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.database.database import init_db
from src.services.auth_service import verify_session
from dashboard.theme import (
    apply_soc_theme, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC,
    COLOR_TEXT_MUTED, COLOR_SURFACE, COLOR_BORDER_SUBTLE, COLOR_ELEVATED,
    COLOR_SAFE, COLOR_CRITICAL, render_status_badge, render_severity_badge
)

st.set_page_config(
    page_title="NetSentry SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize database schema
init_db()

# Apply NetSentry dark theme
apply_soc_theme()

# ── Session State Initialization ────────────────────────────────────────────
if "session_token" not in st.session_state:
    st.session_state["session_token"] = None
if "current_page" not in st.session_state:
    st.session_state["current_page"] = "Overview"
if "selected_alert_id" not in st.session_state:
    st.session_state["selected_alert_id"] = None

current_user = verify_session(st.session_state["session_token"]) if st.session_state["session_token"] else None

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    # Logo / Branding
    st.markdown(f"""
    <div style="padding: 0.5rem 0 1rem 0; border-bottom: 1px solid {COLOR_BORDER_SUBTLE}; margin-bottom: 0.5rem;">
        <div style="display:flex; align-items:center; gap: 0.65rem;">
            <span style="font-size:1.7rem; line-height:1;">🛡️</span>
            <div>
                <div style="font-size:1.1rem; font-weight:800; color:{COLOR_TEXT}; letter-spacing:-0.02em; line-height:1.1;">NetSentry</div>
                <div style="font-size:0.65rem; text-transform:uppercase; letter-spacing:0.12em; color:{COLOR_TEXT_MUTED}; font-weight:600;">SOC Platform v2.0</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Sensor status indicator
    try:
        from src.ingestion.realworld_sniffer import realworld_sniffer_engine
        sensor_active = realworld_sniffer_engine.is_running()
    except Exception:
        sensor_active = False

    if sensor_active:
        st.markdown(f"""
        <div style="background:rgba(75,175,130,0.08);border:1px solid rgba(75,175,130,0.25);
                    border-radius:6px;padding:0.4rem 0.75rem;margin-bottom:0.75rem;
                    display:flex;align-items:center;gap:0.5rem;font-size:0.78rem;">
            <span class="ns-pulse-dot" style="width:6px;height:6px;"></span>
            <span style="color:{COLOR_SAFE};font-weight:600;">Sensor Active</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background:rgba(100,116,139,0.06);border:1px solid rgba(100,116,139,0.2);
                    border-radius:6px;padding:0.4rem 0.75rem;margin-bottom:0.75rem;
                    display:flex;align-items:center;gap:0.5rem;font-size:0.78rem;">
            <span style="width:6px;height:6px;border-radius:50%;background:#64748B;display:inline-block;"></span>
            <span style="color:{COLOR_TEXT_MUTED};font-weight:500;">Sensor Offline</span>
        </div>
        """, unsafe_allow_html=True)

    # Navigation groups
    pages = {}

    # ── OPERATIONS ──
    st.markdown('<div class="ns-nav-group">Operations</div>', unsafe_allow_html=True)
    ops_pages = {
        "Overview":          ("📊", "dashboard/pages/overview.py"),
        "Real-Time Monitor": ("⚡", "dashboard/pages/realtime_monitor.py"),
        "Network Traffic":   ("🌐", "dashboard/pages/network_traffic.py"),
    }
    for name, (icon, path) in ops_pages.items():
        pages[name] = path

    ops_selection = st.radio(
        "ops_nav", list(ops_pages.keys()),
        format_func=lambda x: f"{ops_pages[x][0]}  {x}",
        label_visibility="collapsed",
        key="ops_radio"
    )

    # ── DETECTION ──
    st.markdown('<div class="ns-nav-group">Detection</div>', unsafe_allow_html=True)
    det_pages = {
        "Alerts":           ("🚨", "dashboard/pages/alerts.py"),
        "C2 Detection":     ("📡", "dashboard/pages/c2_detection.py"),
        "DNS Analysis":     ("🔍", "dashboard/pages/dns_analysis.py"),
        "Connections":      ("⚡", "dashboard/pages/connections.py"),
        "Detection Rules":  ("⚙️", "dashboard/pages/detection_rules.py"),
        "MITRE ATT&CK":     ("⚔️", "dashboard/pages/mitre_attack.py"),
    }
    for name, (icon, path) in det_pages.items():
        pages[name] = path

    det_selection = st.radio(
        "det_nav", list(det_pages.keys()),
        format_func=lambda x: f"{det_pages[x][0]}  {x}",
        label_visibility="collapsed",
        key="det_radio"
    )

    # ── INVESTIGATION ──
    st.markdown('<div class="ns-nav-group">Investigation</div>', unsafe_allow_html=True)
    inv_pages = {
        "Investigation":    ("🔬", "dashboard/pages/investigation.py"),
        "PCAP Analysis":    ("📦", "dashboard/pages/pcap_analysis.py"),
        "IP Investigation": ("🎯", "dashboard/pages/ip_investigation.py"),
        "Cases":            ("📁", "dashboard/pages/cases.py"),
        "Evidence":         ("🗂️", "dashboard/pages/evidence.py"),
    }
    for name, (icon, path) in inv_pages.items():
        pages[name] = path

    inv_selection = st.radio(
        "inv_nav", list(inv_pages.keys()),
        format_func=lambda x: f"{inv_pages[x][0]}  {x}",
        label_visibility="collapsed",
        key="inv_radio"
    )

    # ── PLATFORM ──
    st.markdown('<div class="ns-nav-group">Platform</div>', unsafe_allow_html=True)
    plat_pages = {
        "Reports":          ("📄", "dashboard/pages/reports.py"),
        "Settings":         ("🔧", "dashboard/pages/settings.py"),
        "Login / Auth":     ("🔑", "dashboard/pages/login.py"),
    }
    for name, (icon, path) in plat_pages.items():
        pages[name] = path

    plat_selection = st.radio(
        "plat_nav", list(plat_pages.keys()),
        format_func=lambda x: f"{plat_pages[x][0]}  {x}",
        label_visibility="collapsed",
        key="plat_radio"
    )

    st.divider()

    # User info footer
    if current_user:
        role = current_user['role']
        role_color = COLOR_CRITICAL if role == "ADMIN" else COLOR_LOW
        st.markdown(f"""
        <div style="padding: 0.75rem; background:{COLOR_ELEVATED}; border:1px solid {COLOR_BORDER_SUBTLE};
                    border-radius:8px; margin-top: 0.5rem;">
            <div style="font-size:0.82rem; font-weight:600; color:{COLOR_TEXT};">
                👤 {current_user['username']}
            </div>
            <div style="margin-top:0.3rem;">
                <span style="font-size:0.68rem; font-weight:600; text-transform:uppercase;
                             letter-spacing:0.06em; color:{role_color};
                             background:rgba(255,255,255,0.05);
                             border:1px solid rgba(255,255,255,0.1);
                             border-radius:4px; padding:0.1em 0.5em;">{role}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Logout", key="sidebar_logout", use_container_width=True):
            st.session_state["session_token"] = None
            st.session_state["current_page"] = "Login / Auth"
            st.rerun()
    else:
        st.markdown(f"""
        <div style="padding:0.6rem;background:rgba(224,82,82,0.06);border:1px solid rgba(224,82,82,0.2);
                    border-radius:6px;font-size:0.8rem;color:{COLOR_TEXT_MUTED};">
            🔒 Not authenticated
        </div>
        """, unsafe_allow_html=True)

# ── Determine active page from radio selections ───────────────────────────────
# Priority: whichever radio changed last
all_radios = {
    **{k: v for k, v in ops_pages.items()},
    **{k: v for k, v in det_pages.items()},
    **{k: v for k, v in inv_pages.items()},
    **{k: v for k, v in plat_pages.items()},
}

# Track which group is "active" by seeing which selection matches session_state
current_page_name = st.session_state.get("current_page", "Overview")

# Figure out if user clicked a new nav item
all_selections = {
    "ops_radio":  ops_selection,
    "det_radio":  det_selection,
    "inv_radio":  inv_selection,
    "plat_radio": plat_selection,
}

# Determine which group the current page belongs to
def get_group_for_page(page_name):
    if page_name in ops_pages:   return "ops_radio"
    if page_name in det_pages:   return "det_radio"
    if page_name in inv_pages:   return "inv_radio"
    if page_name in plat_pages:  return "plat_radio"
    return "ops_radio"

active_group = get_group_for_page(current_page_name)

# Check if any radio differs from expected (user clicked something new)
expected_selections = {
    "ops_radio":  current_page_name if current_page_name in ops_pages  else ops_selection,
    "det_radio":  current_page_name if current_page_name in det_pages  else det_selection,
    "inv_radio":  current_page_name if current_page_name in inv_pages  else inv_selection,
    "plat_radio": current_page_name if current_page_name in plat_pages else plat_selection,
}

# Find the first group whose selection changed
new_page = current_page_name
for group_key, sel in all_selections.items():
    if group_key != active_group and sel != expected_selections.get(group_key):
        new_page = sel
        break
    elif group_key == active_group and sel != current_page_name:
        new_page = sel
        break

if new_page != current_page_name:
    st.session_state["current_page"] = new_page
    current_page_name = new_page

# ── Load active page ──────────────────────────────────────────────────────────
page_file = pages.get(current_page_name, "dashboard/pages/overview.py")

# Redirect to login if not authenticated and page is not login
protected_pages = set(pages.keys()) - {"Login / Auth"}
if current_page_name in protected_pages and not current_user:
    page_file = "dashboard/pages/login.py"

try:
    with open(page_file, "r", encoding="utf-8") as f:
        code = compile(f.read(), page_file, "exec")
        exec(code, globals())
except FileNotFoundError:
    st.error(f"Page file not found: `{page_file}`")
    st.info("This page is coming soon. Navigate to another section.")
except Exception as e:
    st.error(f"Error loading page '{current_page_name}': {e}")
    import traceback
    st.code(traceback.format_exc())
