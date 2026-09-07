import streamlit as st
import time
import pandas as pd
from src.services.admin_permission_service import (
    get_admin_permission_status,
    grant_admin_permission,
    revoke_admin_permission
)
from src.ingestion.realtime_sniffer import _global_sniffer
from src.database.realtime_db import realtime_bus
from src.services.realtime_pipeline import realtime_pipeline_manager

st.title("⚡ Real-Time Live Packet Monitor & Issue Generator")
st.caption("Live network packet sniffer, admin permission governance, and streaming issue emitter")

perm_status = get_admin_permission_status()

# 1. Admin Permission Control Panel
with st.container():
    c_perm, c_act = st.columns([3, 1])
    with c_perm:
        if perm_status["is_granted"]:
            st.success(f"🟢 **ADMIN PERMISSION GRANTED** by `{perm_status.get('granted_by', 'Admin')}` at {perm_status.get('granted_at')}")
        else:
            st.warning("🔴 **ADMIN PERMISSION REVOKED** — Live packet scanning disabled. Admin consent required.")
    with c_act:
        if perm_status["is_granted"]:
            if st.button("Revoke Permission ⛔"):
                revoke_admin_permission("Local_Admin")
                if _global_sniffer.is_running():
                    _global_sniffer.stop_sniffing()
                st.toast("Admin permission REVOKED!")
                st.rerun()
        else:
            if st.button("Grant Admin Permission 🔓", type="primary"):
                grant_admin_permission("Local_Admin")
                st.toast("Admin permission GRANTED!")
                st.rerun()

st.divider()

# 2. Live Sniffer Control
if perm_status["is_granted"]:
    st.subheader("📡 Live Packet Sniffer Control")
    cs1, cs2, cs3 = st.columns([2, 1, 1])
    
    with cs1:
        iface_input = st.text_input("Network Interface", value="eth0", help="Use 'eth0', 'wlan0', 'lo', or 'all'")
    with cs2:
        is_active = _global_sniffer.is_running()
        st.markdown(f"**Sniffer Status**: {'🟢 RUNNING' if is_active else '⚪ STOPPED'}")
    with cs3:
        if not is_active:
            if st.button("Start Live Sniffing ▶"):
                _global_sniffer.callback_fn = realtime_pipeline_manager.handle_live_event
                _global_sniffer.start_sniffing(interface=iface_input)
                st.toast("Real-time sniffer started!")
                st.rerun()
        else:
            if st.button("Stop Sniffing ⏹"):
                _global_sniffer.stop_sniffing()
                st.toast("Sniffer stopped.")
                st.rerun()

    # 3. Live Streaming Tables & Auto-refresh
    st.divider()
    st.subheader("📊 Live Streaming Packets & Real-Time Alerts")
    
    auto_refresh = st.checkbox("Auto-refresh Live Stream (2s interval)", value=True)
    
    col_p, col_a = st.columns(2)
    
    recent_pkts = realtime_bus.get_recent_packets(limit=25)
    recent_alts = realtime_bus.get_recent_alerts(limit=25)
    
    with col_p:
        st.markdown(f"##### Live Packets Captured (`{_global_sniffer.packets_captured_count}` total)")
        if recent_pkts:
            df_pkts = pd.DataFrame(recent_pkts)
            st.dataframe(df_pkts, use_container_width=True, hide_index=True)
        else:
            st.info("No packets captured yet in current streaming window.")
            
    with col_a:
        st.markdown("##### Real-Time Issues & Alerts Raised")
        if recent_alts:
            df_alts = pd.DataFrame(recent_alts)
            st.dataframe(df_alts, use_container_width=True, hide_index=True)
        else:
            st.info("No live issues raised yet in streaming buffer.")

    if auto_refresh and _global_sniffer.is_running():
        time.sleep(2)
        st.rerun()
else:
    st.info("ℹ️ Please grant Admin permission above to enable real-time network packet scanning.")
