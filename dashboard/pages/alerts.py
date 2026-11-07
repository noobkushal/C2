import streamlit as st
import pandas as pd
from src.database.repositories import get_alerts, update_alert_status
from src.services.auth_service import verify_session
from src.services.mitre_mapping import get_mitre_context
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BORDER,
    render_page_header, render_severity_badge, render_status_badge, section_heading
)

render_page_header(
    "Alert Management & Triage",
    "Active detection alerts — acknowledge, investigate, resolve, dismiss, or escalate to a case",
    "🚨"
)

current_user = verify_session(st.session_state.get("session_token")) if st.session_state.get("session_token") else None

# ─── MITRE tag renderer ────────────────────────────────────────────────────────
def render_mitre_tags(alert_type: str) -> str:
    techniques = get_mitre_context(alert_type)
    if not techniques:
        return ""
    tags_html = ""
    for t in techniques[:2]:  # Show at most 2 tags inline
        tid  = t["technique_id"]
        url  = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        tags_html += (
            f'<a href="{url}" target="_blank" rel="noopener" '
            f'style="display:inline-flex;align-items:center;gap:0.25em;'
            f'font-size:0.67rem;font-weight:600;text-transform:uppercase;'
            f'letter-spacing:0.06em;color:{COLOR_ACCENT};'
            f'background:rgba(216,137,85,0.08);border:1px solid rgba(216,137,85,0.25);'
            f'border-radius:4px;padding:0.1em 0.5em;text-decoration:none;'
            f'margin-right:0.25rem;">'
            f'⚔ {tid}</a>'
        )
    return tags_html

# ─── Case creation helper ──────────────────────────────────────────────────────
def create_case_from_alert(alert_row: pd.Series) -> str:
    """Creates a case pre-filled from an alert row and returns the new case_id."""
    import uuid
    from src.database.database import get_db_connection, _db_lock
    from src.utils.time_utils import current_iso8601

    case_id = str(uuid.uuid4())
    now     = current_iso8601()
    title   = f"{alert_row['alert_type']} — {alert_row['source_ip']} → {alert_row['destination_ip']}"
    desc    = (
        f"Auto-created from Alert {alert_row['alert_id'][:8]}.\n"
        f"Risk score: {alert_row['risk_score']}  |  Severity: {alert_row['severity']}\n"
        f"Reason: {str(alert_row.get('reason',''))[:200]}"
    )
    severity = alert_row.get("severity", "MEDIUM").upper()
    creator  = current_user["username"] if current_user else "system"
    linked   = alert_row["alert_id"]

    # Ensure cases table exists
    with _db_lock:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT,
            severity TEXT NOT NULL DEFAULT 'MEDIUM', status TEXT NOT NULL DEFAULT 'OPEN',
            created_by TEXT NOT NULL, linked_alert_ids TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
        cur.execute(
            "INSERT INTO cases (case_id,title,description,severity,status,created_by,linked_alert_ids,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (case_id, title, desc, severity, "OPEN", creator, linked, now, now)
        )
        conn.commit()
        conn.close()

    # Also auto-acknowledge the alert
    update_alert_status(alert_row["alert_id"], "INVESTIGATING")
    return case_id

# ─── Bulk triage state helpers ─────────────────────────────────────────────────
if "bulk_selected" not in st.session_state:
    st.session_state["bulk_selected"] = set()

def toggle_select(alert_id: str):
    sel = st.session_state["bulk_selected"]
    if alert_id in sel:
        sel.discard(alert_id)
    else:
        sel.add(alert_id)

# ─── Filters ──────────────────────────────────────────────────────────────────
with st.container():
    f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
    with f1:
        severity_filter = st.selectbox(
            "Severity", options=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            label_visibility="visible"
        )
    with f2:
        alert_type_filter = st.selectbox(
            "Alert Type",
            options=["ALL", "BEACONING", "DNS_ANOMALY", "RARE_DESTINATION",
                     "HIGH_FREQUENCY", "SUSPICIOUS_PORT", "PORT_SCAN"],
        )
    with f3:
        status_filter_ui = st.selectbox(
            "Status",
            options=["ALL", "NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"]
        )
    with f4:
        src_search = st.text_input("Search IP / Reason", placeholder="e.g. 192.168.1.10 or C2")

# ─── Bulk action bar ──────────────────────────────────────────────────────────
bulk_selected = st.session_state["bulk_selected"]
if bulk_selected:
    n = len(bulk_selected)
    bbar_cols = st.columns([3, 1.5, 1.5, 1.5, 1.5, 1])
    with bbar_cols[0]:
        st.markdown(
            f'<div style="padding:0.55rem 0;font-size:0.85rem;font-weight:600;color:{COLOR_ACCENT};">'
            f'  {n} alert{"s" if n != 1 else ""} selected</div>',
            unsafe_allow_html=True
        )
    with bbar_cols[1]:
        if st.button("✓ Acknowledge All", use_container_width=True, key="bulk_ack"):
            for aid in bulk_selected:
                update_alert_status(aid, "INVESTIGATING")
            st.session_state["bulk_selected"] = set()
            st.toast(f"Acknowledged {n} alerts", icon="✓")
            st.rerun()
    with bbar_cols[2]:
        if st.button("✅ Resolve All", use_container_width=True, key="bulk_resolve"):
            for aid in bulk_selected:
                update_alert_status(aid, "CLOSED")
            st.session_state["bulk_selected"] = set()
            st.toast(f"Resolved {n} alerts", icon="✅")
            st.rerun()
    with bbar_cols[3]:
        if st.button("🚫 False Pos. All", use_container_width=True, key="bulk_fp"):
            for aid in bulk_selected:
                update_alert_status(aid, "FALSE_POSITIVE")
            st.session_state["bulk_selected"] = set()
            st.toast(f"Marked {n} alerts as false positive", icon="🚫")
            st.rerun()
    with bbar_cols[4]:
        if st.button("📁 Create Cases", use_container_width=True, key="bulk_case"):
            # Create one case per selected alert
            count = 0
            for aid in list(bulk_selected):
                try:
                    row_df = get_alerts(limit=1)
                    # Fetch the specific alert row
                    from src.database.database import get_db_connection
                    conn = get_db_connection()
                    cur  = conn.cursor()
                    cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (aid,))
                    row = cur.fetchone()
                    conn.close()
                    if row:
                        row_series = pd.Series(dict(row))
                        create_case_from_alert(row_series)
                        count += 1
                except Exception:
                    pass
            st.session_state["bulk_selected"] = set()
            st.toast(f"Created {count} cases", icon="📁")
            st.rerun()
    with bbar_cols[5]:
        if st.button("✕ Clear", use_container_width=True, key="bulk_clear"):
            st.session_state["bulk_selected"] = set()
            st.rerun()

st.divider()

# ─── Alert card renderer ───────────────────────────────────────────────────────
def render_alerts(status_val: str, severity: str, atype: str, src: str):
    sev    = severity if severity != "ALL" else None
    at     = atype if atype != "ALL" else None
    status = status_val if status_val not in ("ALL", None) else None

    alerts_df = get_alerts(
        status=status,
        severity=sev,
        alert_type=at,
        source_ip=src or None,
        limit=200
    )

    if src:
        alerts_df = alerts_df[
            alerts_df["source_ip"].str.contains(src, na=False) |
            alerts_df["destination_ip"].str.contains(src, na=False) |
            alerts_df["reason"].str.contains(src, case=False, na=False)
        ]

    if alerts_df.empty:
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                    border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:1rem 0;">
            <div style="font-size:1.2rem;margin-bottom:0.3rem;">🔔</div>
            No alerts match the selected filters.
        </div>
        """, unsafe_allow_html=True)
        return

    count = len(alerts_df)
    sel_count = len(st.session_state["bulk_selected"])
    st.markdown(f"""
    <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-bottom:0.75rem;">
        {count} alert{'s' if count != 1 else ''} found
        {f' &nbsp;·&nbsp; <span style="color:{COLOR_ACCENT};">{sel_count} selected</span>' if sel_count else ''}
    </div>
    """, unsafe_allow_html=True)

    for idx, row in alerts_df.iterrows():
        alert_id  = row["alert_id"]
        sev_val   = row["severity"].upper()
        is_selected = alert_id in st.session_state["bulk_selected"]

        sev_color_map = {
            "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
        }
        left_border = sev_color_map.get(sev_val, COLOR_LOW)
        card_bg     = f"rgba(216,137,85,0.04)" if is_selected else COLOR_SURFACE
        card_border = COLOR_ACCENT if is_selected else COLOR_BORDER_SUBTLE

        # MITRE tags HTML
        mitre_html = render_mitre_tags(row["alert_type"])

        # Alert card
        st.markdown(f"""
        <div style="background:{card_bg};border:1px solid {card_border};
                    border-left:3px solid {left_border};border-radius:8px;
                    padding:0.9rem 1.25rem;margin-bottom:0.2rem;">
            <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.35rem;flex-wrap:wrap;">
                {render_severity_badge(sev_val)}
                {render_status_badge(row['status'])}
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;
                             color:{COLOR_TEXT};font-weight:500;">{row['alert_type']}</span>
                <span style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};">
                    Score: <strong style="color:{COLOR_ACCENT};">{row['risk_score']}</strong>
                </span>
                {mitre_html}
                <span style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};margin-left:auto;">
                    {str(row.get('last_seen',''))[:16]}
                </span>
            </div>
            <div style="font-size:0.82rem;color:{COLOR_TEXT_SEC};">
                <code style="background:{COLOR_ELEVATED};font-size:0.78rem;
                             padding:0.1em 0.4em;border-radius:3px;">{row['source_ip']}</code>
                <span style="color:{COLOR_TEXT_MUTED};margin:0 0.5rem;">→</span>
                <code style="background:{COLOR_ELEVATED};font-size:0.78rem;
                             padding:0.1em 0.4em;border-radius:3px;">{row['destination_ip']}:{row.get('destination_port','?')}</code>
                <span style="color:{COLOR_TEXT_MUTED};margin-left:0.75rem;">
                    {str(row.get('reason',''))[:140]}{'…' if len(str(row.get('reason',''))) > 140 else ''}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Action row ────────────────────────────────────────────────────────
        a1, a2, a3, a4, a5, a6, a7 = st.columns([0.7, 1.4, 1.4, 1.4, 1.4, 1.4, 2.2])

        # Checkbox (bulk select)
        with a1:
            chk = st.checkbox(
                "sel",
                value=is_selected,
                key=f"chk_{alert_id}_{idx}",
                label_visibility="collapsed"
            )
            if chk != is_selected:
                toggle_select(alert_id)
                st.rerun()

        # Inspect → Investigation page
        with a2:
            if st.button("🔍 Inspect", key=f"inspect_{alert_id}_{idx}", use_container_width=True):
                st.session_state["selected_alert_id"] = alert_id
                st.session_state["current_page"]      = "Investigation"
                st.rerun()

        # Investigate IP → IP Investigation page
        with a3:
            if st.button("🎯 IP Intel", key=f"ipintel_{alert_id}_{idx}", use_container_width=True):
                st.session_state["investigate_ip"] = row["source_ip"]
                st.session_state["current_page"]   = "IP Investigation"
                st.rerun()

        # Acknowledge
        with a4:
            if row["status"] == "NEW":
                if st.button("✓ Ack", key=f"ack_{alert_id}_{idx}", use_container_width=True):
                    update_alert_status(alert_id, "INVESTIGATING")
                    st.toast("Alert acknowledged", icon="✓")
                    st.rerun()
            elif row["status"] == "INVESTIGATING":
                if st.button("✅ Confirm", key=f"confirm_{alert_id}_{idx}", use_container_width=True):
                    update_alert_status(alert_id, "CONFIRMED")
                    st.toast("Alert confirmed", icon="✅")
                    st.rerun()

        # Resolve / False Positive
        with a5:
            if row["status"] not in ("CLOSED", "FALSE_POSITIVE"):
                if st.button("✅ Resolve", key=f"resolve_{alert_id}_{idx}", use_container_width=True):
                    update_alert_status(alert_id, "CLOSED")
                    st.toast("Alert resolved", icon="✅")
                    st.rerun()

        with a6:
            if row["status"] not in ("FALSE_POSITIVE", "CLOSED"):
                if st.button("🚫 False+", key=f"fp_{alert_id}_{idx}", use_container_width=True):
                    update_alert_status(alert_id, "FALSE_POSITIVE")
                    st.toast("Marked as false positive", icon="🚫")
                    st.rerun()

        # Expander: Create Case + Add Note
        with a7:
            with st.expander("📁 Case / 📝 Note"):
                action_choice = st.radio(
                    "Action",
                    ["Create Case from this Alert", "Add Analyst Note"],
                    key=f"action_choice_{alert_id}_{idx}",
                    label_visibility="collapsed",
                    horizontal=True,
                )
                if action_choice == "Create Case from this Alert":
                    if st.button(
                        "📁 Create Case",
                        key=f"create_case_{alert_id}_{idx}",
                        type="primary",
                        use_container_width=True
                    ):
                        try:
                            cid = create_case_from_alert(row)
                            st.session_state["selected_case_id"] = cid
                            st.toast("Case created — alert acknowledged", icon="📁")
                            # Give user a jump link
                            st.session_state["_case_created_id"] = cid
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error creating case: {e}")
                else:
                    note_text = st.text_input(
                        "Note",
                        key=f"note_{alert_id}_{idx}",
                        placeholder="Analyst observation…",
                        label_visibility="collapsed"
                    )
                    if st.button("💾 Save Note", key=f"save_note_{alert_id}_{idx}", use_container_width=True):
                        if note_text.strip():
                            from src.database.repositories import upsert_investigation
                            upsert_investigation(alert_id=alert_id, new_note=note_text.strip())
                            st.toast("Note saved to investigation record", icon="💾")
                            st.rerun()
                        else:
                            st.warning("Note is empty.")

        st.markdown("<div style='height:0.4rem;'></div>", unsafe_allow_html=True)

# ─── Post-case-creation banner ────────────────────────────────────────────────
if st.session_state.get("_case_created_id"):
    cid = st.session_state.pop("_case_created_id")
    st.markdown(f"""
    <div style="background:rgba(75,175,130,0.08);border:1px solid rgba(75,175,130,0.25);
                border-radius:8px;padding:0.75rem 1.25rem;margin-bottom:1rem;
                display:flex;align-items:center;justify-content:space-between;">
        <div style="font-size:0.85rem;">
            <strong style="color:{COLOR_SAFE};">📁 Case created</strong>
            <span style="color:{COLOR_TEXT_MUTED};margin-left:0.5rem;">ID: <code>{cid[:8]}…</code></span>
        </div>
        <span style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};">Navigate to <strong>Cases</strong> to view it.</span>
    </div>
    """, unsafe_allow_html=True)

# ─── Tabbed view ──────────────────────────────────────────────────────────────
tabs = st.tabs(["All", "🔵 New", "🟡 Investigating", "🔴 Confirmed", "⚪ False Positive", "Closed"])
tab_status_map = [
    "ALL", "NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"
]

for tab, tab_status in zip(tabs, tab_status_map):
    with tab:
        render_alerts(
            status_val=tab_status,
            severity=severity_filter,
            atype=alert_type_filter,
            src=src_search
        )
