import streamlit as st
import time
import pandas as pd
from src.services.auth_service import verify_session, has_role
from src.services.admin_permission_service import (
    get_admin_permission_status,
    grant_admin_permission,
    revoke_admin_permission
)
from src.ingestion.realworld_sniffer import realworld_sniffer_engine, list_active_interfaces
from src.database.realtime_db import realtime_bus
from src.services.realworld_pipeline import realworld_pipeline

st.title("⚡ Real-World Live Packet Scanner & Issue Engine")
st.caption("Active physical network card scanning, RBAC authorization, and real live threat detection")

# Verify Authentication
token = st.session_state.get("session_token")
current_user = verify_session(token) if token else None

if not current_user:
    st.warning("🔒 **AUTHENTICATION REQUIRED**: Please go to **Login / Auth** page and log in (Default Admin: `admin` / `Admin@123`).")
    st.stop()

is_admin = has_role(current_user, "ADMIN")
perm_status = get_admin_permission_status()

# 1. Admin Permission Control Panel
with st.container():
    c_perm, c_act = st.columns([3, 1])
    with c_perm:
        if perm_status["is_granted"]:
            st.success(f"🟢 **ADMIN CONSENT GRANTED** by `{perm_status.get('granted_by', 'Admin')}` at {perm_status.get('granted_at')}")
        else:
            st.warning("🔴 **ADMIN CONSENT REVOKED** — Live packet scanning disabled.")
    with c_act:
        if is_admin:
            if perm_status["is_granted"]:
                if st.button("Revoke Permission ⛔"):
                    revoke_admin_permission(current_user["username"])
                    if realworld_sniffer_engine.is_running():
                        realworld_sniffer_engine.stop_sniffing()
                    st.toast("Admin permission REVOKED!")
                    st.rerun()
            else:
                if st.button("Grant Admin Permission 🔓", type="primary"):
                    grant_admin_permission(current_user["username"])
                    st.toast("Admin permission GRANTED!")
                    st.rerun()
        else:
            st.error("Only ADMIN accounts can modify consent settings.")

st.divider()

# 2. Real-World Live Packet Sniffer Control
if perm_status["is_granted"]:
    st.subheader("📡 Real-World Physical Network Interface Scanner")
    cs1, cs2, cs3 = st.columns([2, 1, 1])
    
    active_ifaces = list_active_interfaces()
    with cs1:
        iface_input = st.selectbox("Select Active Physical Network Adapter", options=active_ifaces)
    with cs2:
        is_active = realworld_sniffer_engine.is_running()
        st.markdown(f"**Live NIC Status**: {'🟢 SCANNING LIVE' if is_active else '⚪ STOPPED'}")
    with cs3:
        if not is_active:
            if st.button("Start Live NIC Scanning ▶", disabled=not is_admin, type="primary"):
                try:
                    realworld_sniffer_engine.callback_fn = realworld_pipeline.handle_realworld_packet
                    realworld_sniffer_engine.start_sniffing(interface=iface_input, user_obj=current_user)
                    st.toast(f"Live network scanning started on {iface_input}!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error starting live packet scanner: {e}")
        else:
            if st.button("Stop Scanning ⏹"):
                realworld_sniffer_engine.stop_sniffing()
                st.toast("Sniffer stopped.")
                st.rerun()

    # 3. Live Streaming Tables & Auto-refresh
    st.divider()
    st.subheader("📊 Real-World Live Packets & Real-Time Alerts")
    
    auto_refresh = st.checkbox("Auto-refresh Live Network Stream (2s interval)", value=True)
    
    col_p, col_a = st.columns(2)
    
    recent_pkts = realtime_bus.get_recent_packets(limit=25)
    recent_alts = realtime_bus.get_recent_alerts(limit=25)
    
    with col_p:
        st.markdown(f"##### Live Packets Captured (`{realworld_sniffer_engine.packets_captured_count}` total)")
        if recent_pkts:
            df_pkts = pd.DataFrame(recent_pkts)
            st.dataframe(df_pkts, use_container_width=True, hide_index=True)
        else:
            st.info("Waiting for live packets traversing selected network interface...")
            
    with col_a:
        st.markdown("##### Real-Time Raised Issues & Alerts")
        if recent_alts:
            df_alts = pd.DataFrame(recent_alts)
            st.dataframe(df_alts, use_container_width=True, hide_index=True)
        else:
            st.info("No anomalous issues detected yet in real-time stream.")

    if auto_refresh and realworld_sniffer_engine.is_running():
        time.sleep(2)
        st.rerun()
else:
    st.info("ℹ️ Please grant Admin Consent above to enable real-world physical network scanning.")
