import streamlit as st
from src.services.auth_service import verify_session, has_role
from src.utils.config_loader import load_app_config, load_detection_rules
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BORDER,
    render_page_header, section_heading
)

render_page_header(
    "System Settings & Control Panel",
    "User management, security, detection configuration, and system operations",
    "🔧"
)

# ─── Auth check ───────────────────────────────────────────────────────────────
current_user = verify_session(st.session_state.get("session_token")) if st.session_state.get("session_token") else None
is_admin     = has_role(current_user, "ADMIN") if current_user else False

if not current_user:
    st.markdown(f"""
    <div style="background:rgba(224,82,82,0.08);border:1px solid rgba(224,82,82,0.25);
                border-radius:8px;padding:1.5rem;text-align:center;">
        <div style="font-size:1.2rem;margin-bottom:0.5rem;">🔒</div>
        <div style="font-weight:600;color:{COLOR_CRITICAL};">Authentication Required</div>
        <div style="font-size:0.83rem;color:{COLOR_TEXT_SEC};margin-top:0.3rem;">
            Please log in to access settings.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Settings tabs ────────────────────────────────────────────────────────────
tabs = st.tabs([
    "👤  My Profile",
    "👥  User Management",
    "🔬  Detection Rules",
    "🛠️  Operations",
    "🔌  Threat Intel",
    "📋  System Info",
])

# ─────────────────────────────────────────────────────────────────────────────
# TAB 1: My Profile (password change)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[0]:
    section_heading("Account Information")
    role = current_user['role']
    role_color = COLOR_CRITICAL if role == "ADMIN" else COLOR_LOW
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:1.25rem 1.5rem;margin-bottom:1rem;">
        <div style="display:flex;align-items:center;gap:1rem;">
            <div style="width:48px;height:48px;border-radius:50%;
                        background:{COLOR_ELEVATED};border:2px solid {role_color};
                        display:flex;align-items:center;justify-content:center;
                        font-size:1.4rem;">👤</div>
            <div>
                <div style="font-size:1rem;font-weight:600;color:{COLOR_TEXT};">{current_user['username']}</div>
                <div style="margin-top:0.2rem;">
                    <span style="font-size:0.72rem;font-weight:700;text-transform:uppercase;
                                 letter-spacing:0.08em;color:{role_color};
                                 background:{role_color}15;border:1px solid {role_color}33;
                                 border-radius:4px;padding:0.1em 0.55em;">{role}</span>
                </div>
                <div style="font-size:0.76rem;color:{COLOR_TEXT_MUTED};margin-top:0.3rem;">
                    Account created: {current_user.get('created_at', 'N/A')[:10]}
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    section_heading("Change Password")
    with st.form("change_password_form"):
        current_pwd  = st.text_input("Current Password", type="password", placeholder="Enter current password")
        new_pwd      = st.text_input("New Password", type="password", placeholder="Minimum 8 characters")
        confirm_pwd  = st.text_input("Confirm New Password", type="password", placeholder="Repeat new password")

        if st.form_submit_button("🔐  Change Password", type="primary"):
            if not current_pwd or not new_pwd or not confirm_pwd:
                st.error("All fields are required.")
            elif new_pwd != confirm_pwd:
                st.error("New passwords do not match.")
            elif len(new_pwd) < 8:
                st.error("New password must be at least 8 characters.")
            else:
                # Verify current password
                from src.services.auth_service import authenticate_user
                verified = authenticate_user(current_user['username'], current_pwd)
                if not verified:
                    st.error("Current password is incorrect.")
                else:
                    try:
                        from src.services.auth_service import change_password
                        change_password(current_user['user_id'], new_pwd)
                        st.success("✅ Password changed successfully.")
                    except AttributeError:
                        # Fallback if change_password not yet added
                        from src.services.auth_service import hash_password
                        from src.database.database import get_db_connection, _db_lock
                        from src.utils.time_utils import current_iso8601
                        new_hash, new_salt = hash_password(new_pwd)
                        with _db_lock:
                            conn = get_db_connection()
                            conn.cursor().execute(
                                "UPDATE users SET password_hash=?, salt=?, created_at=? WHERE user_id=?",
                                (new_hash, new_salt, current_iso8601(), current_user['user_id'])
                            )
                            conn.commit()
                            conn.close()
                        st.success("✅ Password changed successfully.")
                    except Exception as e:
                        st.error(f"Error changing password: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 2: User Management (ADMIN only)
# ─────────────────────────────────────────────────────────────────────────────
with tabs[1]:
    if not is_admin:
        st.markdown(f"""
        <div style="background:rgba(224,82,82,0.08);border:1px solid rgba(224,82,82,0.25);
                    border-radius:8px;padding:1.25rem;text-align:center;">
            <div style="font-weight:600;color:{COLOR_CRITICAL};">Admin Role Required</div>
            <div style="font-size:0.83rem;color:{COLOR_TEXT_SEC};margin-top:0.3rem;">
                User management is restricted to ADMIN accounts.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        section_heading("Current Users")
        try:
            from src.database.database import get_db_connection
            conn  = get_db_connection()
            cur   = conn.cursor()
            cur.execute("SELECT user_id, username, role, created_at FROM users ORDER BY created_at")
            users = cur.fetchall()
            conn.close()

            for u in users:
                r_color = COLOR_CRITICAL if u[2] == "ADMIN" else COLOR_LOW
                st.markdown(f"""
                <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                            border-radius:7px;padding:0.75rem 1.25rem;margin-bottom:0.4rem;
                            display:flex;align-items:center;justify-content:space-between;">
                    <div>
                        <span style="font-weight:600;color:{COLOR_TEXT};">{u[1]}</span>
                        <span style="font-size:0.72rem;font-weight:600;text-transform:uppercase;
                                     letter-spacing:0.06em;color:{r_color};
                                     background:{r_color}15;border:1px solid {r_color}33;
                                     border-radius:4px;padding:0.1em 0.5em;margin-left:0.6rem;">{u[2]}</span>
                    </div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:{COLOR_TEXT_MUTED};">
                        {str(u[3])[:10]}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Error loading users: {e}")

        st.divider()
        section_heading("Create New User")
        with st.form("create_user_form"):
            new_username = st.text_input("Username", placeholder="e.g. analyst2")
            new_role     = st.selectbox("Role", ["ANALYST", "ADMIN"])
            new_password = st.text_input("Initial Password", type="password", placeholder="Min 8 chars")
            if st.form_submit_button("➕  Create User", type="primary"):
                if not new_username or not new_password:
                    st.error("Username and password are required.")
                elif len(new_password) < 8:
                    st.error("Password must be at least 8 characters.")
                else:
                    try:
                        import uuid
                        from src.services.auth_service import hash_password
                        from src.database.database import get_db_connection, _db_lock
                        from src.utils.time_utils import current_iso8601
                        pwd_hash, salt = hash_password(new_password)
                        now  = current_iso8601()
                        uid  = str(uuid.uuid4())
                        with _db_lock:
                            conn = get_db_connection()
                            conn.cursor().execute(
                                "INSERT INTO users (user_id, username, password_hash, salt, role, created_at) VALUES (?,?,?,?,?,?)",
                                (uid, new_username, pwd_hash, salt, new_role, now)
                            )
                            conn.commit()
                            conn.close()
                        st.success(f"✅ User '{new_username}' ({new_role}) created.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error creating user: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 3: Detection Rule Thresholds
# ─────────────────────────────────────────────────────────────────────────────
with tabs[2]:
    section_heading("Detection Rule Configuration")
    from src.database.repositories import get_detection_rules, update_detection_rule
    rules = get_detection_rules()

    if not rules:
        st.info("No detection rules found in database.")
    else:
        for r in rules:
            col_a, col_b = st.columns([3, 1])
            with col_a:
                curr_thresh = r.threshold if r.threshold is not None else 0.0
                new_thresh  = st.number_input(
                    f"{r.name} — threshold",
                    min_value=0.0, max_value=10000.0,
                    value=float(curr_thresh), step=0.01,
                    key=f"settings_thresh_{r.rule_id}",
                    help=r.description or ""
                )
                if abs(new_thresh - curr_thresh) > 1e-6:
                    update_detection_rule(r.rule_id, threshold=new_thresh)
                    st.toast(f"Updated {r.rule_id} → {new_thresh}", icon="⚙️")
                    st.rerun()
            with col_b:
                enabled = st.toggle("Active", value=bool(r.enabled), key=f"settings_toggle_{r.rule_id}")
                if enabled != bool(r.enabled):
                    update_detection_rule(r.rule_id, enabled=int(enabled))
                    st.toast(f"{r.rule_id} {'enabled' if enabled else 'disabled'}", icon="⚙️")
                    st.rerun()

# ─────────────────────────────────────────────────────────────────────────────
# TAB 4: Operations
# ─────────────────────────────────────────────────────────────────────────────
with tabs[3]:
    op1, op2 = st.columns(2)

    with op1:
        section_heading("Load Synthetic Sample Data")
        st.markdown(f"""
        <div style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};margin-bottom:1rem;">
            Populates the database with ~1,000 synthetic network &amp; DNS events including
            a beaconing C2 pair. Runs full detection pipeline.
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀  Generate & Load Sample Data", type="primary", use_container_width=True):
            try:
                from scripts.generate_test_data import generate_all_test_data
                from src.services.pipeline import run_detection_only
                with st.spinner("Generating synthetic telemetry…"):
                    counts   = generate_all_test_data()
                    alerts_n = run_detection_only()
                st.success(
                    f"✅ Loaded {counts['net_events']:,} network events, "
                    f"{counts['dns_events']:,} DNS events, "
                    f"{alerts_n} alerts generated."
                )
                st.rerun()
            except Exception as e:
                st.error(f"Error generating sample data: {e}")

    with op2:
        section_heading("Reset Database")
        st.markdown(f"""
        <div style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};margin-bottom:1rem;">
            Wipes all event and alert tables. PCAP files and exported JSON artifacts
            are preserved.
        </div>
        """, unsafe_allow_html=True)
        if not is_admin:
            st.warning("Only ADMIN accounts can reset the database.")
        else:
            confirm_text = st.text_input("Type RESET to confirm:", placeholder="RESET")
            if st.button("⚠️  Wipe & Re-initialize Database",
                         disabled=(confirm_text.strip() != "RESET"),
                         use_container_width=True):
                try:
                    from scripts.reset_db import reset_database
                    reset_database(full=False)
                    st.success("✅ Database reset and re-initialized.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error resetting database: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# TAB 5: Threat Intelligence Integration
# ─────────────────────────────────────────────────────────────────────────────
with tabs[4]:
    from src.services.threat_intel_service import get_api_key, set_api_key, delete_api_key, clear_cache

    section_heading("Threat Intelligence Providers")
    st.markdown(f"""
    <div style="font-size:0.83rem;color:{COLOR_TEXT_MUTED};margin-bottom:1.25rem;">
        Configure API keys for external threat intelligence providers.
        Keys are stored locally in the NetSentry database and never transmitted
        except to the respective provider's API. The cache is cleared automatically after 1 hour.
    </div>
    """, unsafe_allow_html=True)

    # ── AbuseIPDB ──
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                border-left:3px solid {COLOR_ACCENT};border-radius:8px;
                padding:1rem 1.25rem;margin-bottom:1rem;">
        <div style="font-weight:700;color:{COLOR_TEXT};margin-bottom:0.25rem;">
            🛡️ AbuseIPDB
        </div>
        <div style="font-size:0.8rem;color:{COLOR_TEXT_MUTED};">
            IP abuse confidence score, total reports, ISP, country, and whitelist status.
            Free tier: 1,000 checks/day.
            <a href="https://www.abuseipdb.com/account/api" target="_blank"
               style="color:{COLOR_ACCENT};text-decoration:none;">Get API key →</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

    existing_abuse = get_api_key("ABUSEIPDB_API_KEY")
    with st.form("abuseipdb_form"):
        if existing_abuse:
            masked = existing_abuse[:6] + "…" + existing_abuse[-4:] if len(existing_abuse) > 10 else "****"
            st.markdown(
                f'<div style="font-size:0.8rem;color:{COLOR_SAFE};margin-bottom:0.5rem;">'
                f'✅ Configured: <code>{masked}</code></div>',
                unsafe_allow_html=True
            )
        abuse_key_input = st.text_input(
            "AbuseIPDB API Key",
            type="password",
            placeholder="Paste your AbuseIPDB API key here…",
            label_visibility="collapsed"
        )
        a_col1, a_col2 = st.columns([2, 1])
        with a_col1:
            if st.form_submit_button("💾  Save AbuseIPDB Key", type="primary"):
                if abuse_key_input.strip():
                    set_api_key("ABUSEIPDB_API_KEY", abuse_key_input.strip())
                    clear_cache()
                    st.success("✅ AbuseIPDB API key saved.")
                    st.rerun()
                else:
                    st.error("Key cannot be empty.")
        with a_col2:
            if existing_abuse:
                if st.form_submit_button("🗑️  Remove Key"):
                    delete_api_key("ABUSEIPDB_API_KEY")
                    clear_cache()
                    st.success("Key removed.")
                    st.rerun()

    st.divider()

    # ── VirusTotal ──
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                border-left:3px solid {COLOR_LOW};border-radius:8px;
                padding:1rem 1.25rem;margin-bottom:1rem;">
        <div style="font-weight:700;color:{COLOR_TEXT};margin-bottom:0.25rem;">
            🦠 VirusTotal
        </div>
        <div style="font-size:0.8rem;color:{COLOR_TEXT_MUTED};">
            Malicious/suspicious engine votes, reputation score, country, and ASN.
            Free tier: 4 lookups/min, 500/day.
            <a href="https://www.virustotal.com/gui/my-apikey" target="_blank"
               style="color:{COLOR_LOW};text-decoration:none;">Get API key →</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

    existing_vt = get_api_key("VIRUSTOTAL_API_KEY")
    with st.form("virustotal_form"):
        if existing_vt:
            masked_vt = existing_vt[:6] + "…" + existing_vt[-4:] if len(existing_vt) > 10 else "****"
            st.markdown(
                f'<div style="font-size:0.8rem;color:{COLOR_SAFE};margin-bottom:0.5rem;">'
                f'✅ Configured: <code>{masked_vt}</code></div>',
                unsafe_allow_html=True
            )
        vt_key_input = st.text_input(
            "VirusTotal API Key",
            type="password",
            placeholder="Paste your VirusTotal API key here…",
            label_visibility="collapsed"
        )
        v_col1, v_col2 = st.columns([2, 1])
        with v_col1:
            if st.form_submit_button("💾  Save VirusTotal Key", type="primary"):
                if vt_key_input.strip():
                    set_api_key("VIRUSTOTAL_API_KEY", vt_key_input.strip())
                    clear_cache()
                    st.success("✅ VirusTotal API key saved.")
                    st.rerun()
                else:
                    st.error("Key cannot be empty.")
        with v_col2:
            if existing_vt:
                if st.form_submit_button("🗑️  Remove Key"):
                    delete_api_key("VIRUSTOTAL_API_KEY")
                    clear_cache()
                    st.success("Key removed.")
                    st.rerun()

    st.divider()
    st.caption(
        f"🔒 Keys are stored in the local SQLite database only. "
        f"Cache TTL: 1 hour. "
        f"**No providers are active** until a key is saved above."
        if not (existing_abuse or existing_vt) else
        f"🟢 {sum(bool(k) for k in [existing_abuse, existing_vt])} provider(s) active."
    )

# ─────────────────────────────────────────────────────────────────────────────
# TAB 6: System Info
# ─────────────────────────────────────────────────────────────────────────────
with tabs[5]:
    section_heading("Application Configuration")
    app_cfg   = load_app_config()
    rules_cfg = load_detection_rules()

    col_cfg1, col_cfg2 = st.columns(2)
    with col_cfg1:
        st.caption("Application Config")
        st.json(app_cfg)
    with col_cfg2:
        st.caption("Detection Rules Config")
        st.json(rules_cfg)

    st.divider()
    section_heading("Platform Information")
    import sys, platform
    from src.ingestion.realworld_sniffer import HAS_SCAPY
    try:
        import streamlit as _st
        st_version = _st.__version__
    except Exception:
        st_version = "N/A"

    info_rows = [
        ("Python Version",    sys.version.split()[0]),
        ("Platform",          platform.system() + " " + platform.release()),
        ("Streamlit Version", st_version),
        ("Scapy Available",   "Yes" if HAS_SCAPY else "No (socket fallback active)"),
    ]
    for label, value in info_rows:
        st.markdown(f"""
        <div class="ns-data-row">
            <span class="ns-data-label">{label}</span>
            <span class="ns-data-value">{value}</span>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.caption("🌐 **Deployment**: NetSentry SOC — Render / Streamlit Cloud compatible")
