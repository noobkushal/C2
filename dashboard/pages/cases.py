import streamlit as st
import pandas as pd
from datetime import datetime, timezone
from src.services.auth_service import verify_session, has_role
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BORDER,
    render_page_header, render_severity_badge, render_status_badge, section_heading
)

render_page_header(
    "Case Management",
    "Create, track, and manage investigation cases with linked alerts and analyst notes",
    "📁"
)

# ─── Auth check ───────────────────────────────────────────────────────────────
current_user = verify_session(st.session_state.get("session_token")) if st.session_state.get("session_token") else None
if not current_user:
    st.warning("🔒 Please log in to access case management.")
    st.stop()

is_admin    = has_role(current_user, "ADMIN")
analyst     = current_user["username"]

# ─── DB helpers ───────────────────────────────────────────────────────────────
def get_db():
    from src.database.database import get_db_connection
    return get_db_connection()

def init_cases_tables():
    """Ensure cases tables exist."""
    from src.database.database import get_db_connection, _db_lock
    with _db_lock:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id      TEXT PRIMARY KEY,
            title        TEXT NOT NULL,
            description  TEXT,
            severity     TEXT NOT NULL DEFAULT 'MEDIUM',
            status       TEXT NOT NULL DEFAULT 'OPEN',
            created_by   TEXT NOT NULL,
            linked_alert_ids TEXT,
            created_at   TEXT NOT NULL,
            updated_at   TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS case_notes (
            note_id    TEXT PRIMARY KEY,
            case_id    TEXT NOT NULL,
            analyst    TEXT NOT NULL,
            content    TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """)
        conn.commit()
        conn.close()

init_cases_tables()

def get_cases(status_filter: str | None = None) -> pd.DataFrame:
    conn = get_db()
    q    = "SELECT * FROM cases WHERE 1=1"
    params = []
    if status_filter and status_filter != "ALL":
        q += " AND status = ?"
        params.append(status_filter)
    q += " ORDER BY created_at DESC"
    import pandas as _pd
    df = _pd.read_sql_query(q, conn, params=params)
    conn.close()
    return df

def get_case_notes(case_id: str) -> pd.DataFrame:
    conn = get_db()
    import pandas as _pd
    df = _pd.read_sql_query(
        "SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC",
        conn, params=[case_id]
    )
    conn.close()
    return df

def create_case(title: str, description: str, severity: str, linked_alerts: str, created_by: str) -> str:
    import uuid
    from src.database.database import get_db_connection, _db_lock
    from src.utils.time_utils import current_iso8601
    case_id = str(uuid.uuid4())
    now = current_iso8601()
    with _db_lock:
        conn = get_db_connection()
        conn.cursor().execute(
            "INSERT INTO cases (case_id,title,description,severity,status,created_by,linked_alert_ids,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (case_id, title, description, severity, "OPEN", created_by, linked_alerts, now, now)
        )
        conn.commit()
        conn.close()
    return case_id

def add_case_note(case_id: str, analyst: str, content: str):
    import uuid
    from src.database.database import get_db_connection, _db_lock
    from src.utils.time_utils import current_iso8601
    note_id = str(uuid.uuid4())
    now = current_iso8601()
    with _db_lock:
        conn = get_db_connection()
        conn.cursor().execute(
            "INSERT INTO case_notes (note_id,case_id,analyst,content,created_at) VALUES (?,?,?,?,?)",
            (note_id, case_id, analyst, content, now)
        )
        conn.commit()
        conn.close()

def update_case_status(case_id: str, new_status: str):
    from src.database.database import get_db_connection, _db_lock
    from src.utils.time_utils import current_iso8601
    with _db_lock:
        conn = get_db_connection()
        conn.cursor().execute(
            "UPDATE cases SET status=?, updated_at=? WHERE case_id=?",
            (new_status, current_iso8601(), case_id)
        )
        conn.commit()
        conn.close()

# ─── Case list + create split ─────────────────────────────────────────────────
col_list, col_detail = st.columns([2, 3])

with col_list:
    section_heading("Cases")

    status_filter = st.selectbox(
        "Filter by Status",
        ["ALL", "OPEN", "INVESTIGATING", "CLOSED"],
        label_visibility="collapsed"
    )

    cases_df = get_cases(status_filter)

    if cases_df.empty:
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                    border-radius:8px;padding:2rem;text-align:center;color:{COLOR_TEXT_MUTED};">
            <div style="font-size:1.2rem;margin-bottom:0.3rem;">📁</div>
            No cases found.
        </div>
        """, unsafe_allow_html=True)
    else:
        if "selected_case_id" not in st.session_state:
            st.session_state["selected_case_id"] = None

        for _, row in cases_df.iterrows():
            sev = row.get("severity", "MEDIUM").upper()
            sev_colors = {
                "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
            }
            lb = sev_colors.get(sev, COLOR_MEDIUM)
            status_html = render_status_badge(row.get("status", "OPEN"))
            is_selected = st.session_state.get("selected_case_id") == row["case_id"]
            bg = COLOR_ELEVATED if is_selected else COLOR_SURFACE

            if st.button(
                f"📁  {row['title'][:35]}…" if len(row['title']) > 35 else f"📁  {row['title']}",
                key=f"case_btn_{row['case_id']}",
                use_container_width=True,
                type="secondary" if not is_selected else "primary"
            ):
                st.session_state["selected_case_id"] = row["case_id"]
                st.rerun()

            st.markdown(f"""
            <div style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};
                        margin-top:-0.3rem;margin-bottom:0.5rem;padding-left:0.25rem;">
                {status_html}
                <span style="margin-left:0.4rem;color:{lb};font-weight:600;">{sev}</span>
                <span style="margin-left:0.4rem;">{str(row.get('created_at',''))[:10]}</span>
            </div>
            """, unsafe_allow_html=True)

    st.divider()

    # Create case form
    section_heading("New Case")
    with st.form("create_case_form"):
        case_title   = st.text_input("Title", placeholder="e.g. C2 Beacon Investigation — 192.168.1.5")
        case_desc    = st.text_area("Description", placeholder="Summary of the investigation…", height=80)
        case_sev     = st.selectbox("Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

        # Optionally link alerts
        from src.database.repositories import get_alerts
        alerts_df_list = get_alerts(status="NEW", limit=100)
        linked_alert_opt = st.multiselect(
            "Link Alerts (optional)",
            options=alerts_df_list["alert_id"].tolist() if not alerts_df_list.empty else [],
            format_func=lambda x: f"{x[:8]}…"
        )

        if st.form_submit_button("➕  Create Case", type="primary"):
            if not case_title.strip():
                st.error("Title is required.")
            else:
                linked_str = ",".join(linked_alert_opt)
                cid = create_case(
                    title=case_title.strip(),
                    description=case_desc.strip(),
                    severity=case_sev,
                    linked_alerts=linked_str,
                    created_by=analyst
                )
                st.session_state["selected_case_id"] = cid
                st.toast(f"Case created: {case_title}", icon="📁")
                st.rerun()

with col_detail:
    selected_case_id = st.session_state.get("selected_case_id")

    if not selected_case_id:
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                    border-radius:8px;padding:4rem;text-align:center;color:{COLOR_TEXT_MUTED};
                    margin-top:2rem;">
            <div style="font-size:2rem;margin-bottom:0.75rem;">📁</div>
            <div style="font-weight:500;">Select a case to view details</div>
            <div style="font-size:0.8rem;margin-top:0.25rem;">
                Or create a new case using the form on the left.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Load case
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("SELECT * FROM cases WHERE case_id = ?", (selected_case_id,))
        case_row = cur.fetchone()
        conn.close()

        if not case_row:
            st.error("Case not found.")
        else:
            case = dict(case_row)
            sev  = case.get("severity", "MEDIUM").upper()
            sev_colors = {
                "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
            }
            lb = sev_colors.get(sev, COLOR_MEDIUM)

            st.markdown(f"""
            <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                        border-left:4px solid {lb};border-radius:10px;padding:1.25rem 1.5rem;margin-bottom:1rem;">
                <div style="display:flex;align-items:flex-start;justify-content:space-between;">
                    <div style="flex:1;">
                        <div style="font-size:1rem;font-weight:700;color:{COLOR_TEXT};margin-bottom:0.4rem;">
                            {case['title']}
                        </div>
                        <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.4rem;">
                            {render_severity_badge(sev)}
                            {render_status_badge(case.get('status','OPEN'))}
                        </div>
                        <div style="font-size:0.8rem;color:{COLOR_TEXT_MUTED};">
                            Created by <strong>{case.get('created_by','?')}</strong>
                            on {str(case.get('created_at',''))[:10]}
                        </div>
                        {f"<div style='font-size:0.82rem;color:{COLOR_TEXT_SEC};margin-top:0.4rem;'>{case['description']}</div>" if case.get('description') else ""}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Status transition
            section_heading("Case Status")
            status_cols = st.columns(3)
            statuses = ["OPEN", "INVESTIGATING", "CLOSED"]
            for idx, st_name in enumerate(statuses):
                with status_cols[idx]:
                    is_current = case.get("status") == st_name
                    if st.button(
                        st_name,
                        key=f"case_status_{st_name}_{selected_case_id}",
                        type="primary" if is_current else "secondary",
                        use_container_width=True,
                        disabled=is_current
                    ):
                        update_case_status(selected_case_id, st_name)
                        st.toast(f"Case status → {st_name}", icon="✅")
                        st.rerun()

            # Linked alerts
            linked_alert_ids = [x for x in (case.get("linked_alert_ids") or "").split(",") if x]
            if linked_alert_ids:
                section_heading("Linked Alerts")
                for aid in linked_alert_ids:
                    from src.database.repositories import get_alert_by_id
                    a = get_alert_by_id(aid.strip())
                    if a:
                        st.markdown(f"""
                        <div style="font-size:0.8rem;background:{COLOR_ELEVATED};
                                    border:1px solid {COLOR_BORDER_SUBTLE};border-radius:5px;
                                    padding:0.4rem 0.75rem;margin-bottom:0.3rem;">
                            {render_severity_badge(a.severity)}
                            <code style="font-size:0.75rem;">{a.alert_type}</code>
                            {a.source_ip} → {a.destination_ip}
                        </div>
                        """, unsafe_allow_html=True)

            # Notes history
            section_heading("Investigation Notes")
            notes_df = get_case_notes(selected_case_id)
            if not notes_df.empty:
                for _, note in notes_df.iterrows():
                    st.markdown(f"""
                    <div class="ns-note-card">
                        <div class="ns-note-meta">
                            {note['analyst']} · {str(note.get('created_at',''))[:16]}
                        </div>
                        <div>{note['content']}</div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="font-size:0.8rem;color:{COLOR_TEXT_MUTED};padding:0.75rem 0;">
                    No notes yet.
                </div>
                """, unsafe_allow_html=True)

            # Add note
            with st.form(f"add_note_{selected_case_id}"):
                note_content = st.text_area(
                    "Add Note",
                    placeholder="Analyst observation, findings, or action taken…",
                    height=80,
                    label_visibility="collapsed"
                )
                if st.form_submit_button("💾  Add Note", type="primary"):
                    if note_content.strip():
                        add_case_note(selected_case_id, analyst, note_content.strip())
                        st.toast("Note added", icon="💾")
                        st.rerun()
                    else:
                        st.warning("Note cannot be empty.")
