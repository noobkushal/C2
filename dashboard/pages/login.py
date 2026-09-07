import streamlit as st
from src.services.auth_service import authenticate_user, create_session, verify_session

st.title("🔑 Analyst Authentication & Access Control")
st.caption("Secure login portal with Role-Based Access Control (RBAC)")

if "session_token" not in st.session_state:
    st.session_state["session_token"] = None

current_user = verify_session(st.session_state["session_token"]) if st.session_state["session_token"] else None

if current_user:
    st.success(f"Logged in as **{current_user['username']}** (Role: **{current_user['role']}**)")
    st.info("""
    **Default Accounts for Testing**:
    - **Admin Account**: `admin` / `Admin@123` (Full control, live packet capture consent, rule edits)
    - **Analyst Account**: `analyst` / `Analyst@123` (Read-only telemetry, investigate alerts, export reports)
    """)
    if st.button("Logout 🚪"):
        st.session_state["session_token"] = None
        st.rerun()
else:
    st.subheader("Login to SOC Cockpit")
    with st.form("login_form"):
        username = st.text_input("Username", value="admin")
        password = st.text_input("Password", type="password", value="Admin@123")
        submit = st.form_submit_button("Authenticate 🔓")
        
        if submit:
            user = authenticate_user(username, password)
            if user:
                token = create_session(user["user_id"])
                st.session_state["session_token"] = token
                st.success(f"Welcome back, {user['username']}! Role: {user['role']}")
                st.rerun()
            else:
                st.error("Invalid username or password. Default admin credentials: admin / Admin@123")

    st.markdown("---")
    st.caption("🔒 **Security Policy**: Live physical network scanning and rule modifications require an active session with role **ADMIN**.")
