import streamlit as st
from src.services.auth_service import authenticate_user, create_session, verify_session
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, render_severity_badge
)

# ─── Verify existing session ──────────────────────────────────────────────────
if "session_token" not in st.session_state:
    st.session_state["session_token"] = None

current_user = verify_session(st.session_state["session_token"]) if st.session_state["session_token"] else None

# ─── Already logged in ────────────────────────────────────────────────────────
if current_user:
    role = current_user['role']
    role_color = COLOR_CRITICAL if role == "ADMIN" else "#5C8FBE"
    role_bg    = "rgba(224,82,82,0.1)" if role == "ADMIN" else "rgba(92,143,190,0.1)"

    st.markdown(f"""
    <div style="max-width:560px;margin:3rem auto;">
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-radius:12px;padding:2.5rem 2rem;text-align:center;">
            <div style="font-size:3rem;margin-bottom:0.75rem;">✅</div>
            <div style="font-size:1.3rem;font-weight:700;color:{COLOR_TEXT};margin-bottom:0.3rem;">
                Session Active
            </div>
            <div style="font-size:0.9rem;color:{COLOR_TEXT_SEC};margin-bottom:1.5rem;">
                Authenticated as <strong style="color:{COLOR_TEXT};">{current_user['username']}</strong>
            </div>
            <div style="display:inline-block;background:{role_bg};border:1px solid {role_color}33;
                        border-radius:6px;padding:0.4rem 1.2rem;font-size:0.8rem;
                        font-weight:700;color:{role_color};letter-spacing:0.08em;text-transform:uppercase;
                        font-family:'JetBrains Mono',monospace;margin-bottom:1.5rem;">
                {role}
            </div>
            <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-bottom:0.75rem;">
                Account created: {current_user.get('created_at', 'N/A')[:10]}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚪  Sign Out", use_container_width=True):
            st.session_state["session_token"] = None
            st.session_state["current_page"] = "Login / Auth"
            st.rerun()

    st.markdown(f"""
    <div style="max-width:560px;margin:1rem auto;font-size:0.78rem;color:{COLOR_TEXT_MUTED};text-align:center;">
        🔒 RBAC enforced — live packet capture and rule modifications require <strong style="color:{COLOR_CRITICAL};">ADMIN</strong> role.
    </div>
    """, unsafe_allow_html=True)

# ─── Login form ───────────────────────────────────────────────────────────────
else:
    st.markdown(f"""
    <div style="max-width:420px;margin:3rem auto;">
        <div style="text-align:center;margin-bottom:2.5rem;">
            <div style="font-size:3.5rem;line-height:1;margin-bottom:0.75rem;">🛡️</div>
            <div style="font-size:1.75rem;font-weight:800;color:{COLOR_TEXT};letter-spacing:-0.03em;">
                NetSentry SOC
            </div>
            <div style="font-size:0.72rem;text-transform:uppercase;letter-spacing:0.15em;
                        color:{COLOR_TEXT_MUTED};font-weight:600;margin-top:0.35rem;">
                Security Operations Platform
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_l, col_c, col_r = st.columns([1, 4, 1])
    with col_c:
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-radius:12px;padding:2rem 1.75rem;margin-bottom:1rem;">
            <div style="font-size:1rem;font-weight:600;color:{COLOR_TEXT};margin-bottom:1.5rem;">
                Analyst Authentication
            </div>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input(
                "Username",
                placeholder="Enter username",
                help="Contact your SOC administrator for credentials."
            )
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter password"
            )

            st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
            submit = st.form_submit_button(
                "🔓  Authenticate",
                use_container_width=True,
                type="primary"
            )

            if submit:
                if not username or not password:
                    st.error("Please enter both username and password.")
                else:
                    with st.spinner("Verifying credentials…"):
                        user = authenticate_user(username, password)
                    if user:
                        token = create_session(user["user_id"])
                        st.session_state["session_token"] = token
                        st.session_state["current_page"]  = "Overview"
                        st.success(f"Welcome, {user['username']}.")
                        st.rerun()
                    else:
                        st.error("Invalid credentials. Please try again.")

        st.markdown(f"""
        <div style="text-align:center;margin-top:1rem;font-size:0.75rem;color:{COLOR_TEXT_MUTED};">
            🔒 RBAC enforced &nbsp;·&nbsp; Encrypted sessions &nbsp;·&nbsp; Audit logging
        </div>
        """, unsafe_allow_html=True)
