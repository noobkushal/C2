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
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_LOW, COLOR_MEDIUM, COLOR_BORDER,
    render_page_header, section_heading
)

render_page_header(
    "Real-Time Network Monitor",
    "Live packet capture from physical NIC — requires ADMIN authorization and consent",
    "⚡"
)

# ─── Auth check ───────────────────────────────────────────────────────────────
token = st.session_state.get("session_token")
current_user = verify_session(token) if token else None

if not current_user:
    st.markdown(f"""
    <div style="background:rgba(224,82,82,0.08);border:1px solid rgba(224,82,82,0.25);
                border-radius:8px;padding:1.5rem;text-align:center;margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🔒</div>
        <div style="font-weight:600;color:{COLOR_CRITICAL};margin-bottom:0.3rem;">Authentication Required</div>
        <div style="font-size:0.85rem;color:{COLOR_TEXT_SEC};">
            Please go to <strong>Login / Auth</strong> to authenticate before accessing this page.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

is_admin    = has_role(current_user, "ADMIN")
perm_status = get_admin_permission_status()
is_running  = realworld_sniffer_engine.is_running()
pkt_count   = realworld_sniffer_engine.packets_captured_count

# ─── Admin Consent Panel ──────────────────────────────────────────────────────
section_heading("Admin Consent & Authorization")

col_consent, col_action = st.columns([3, 1])

with col_consent:
    if perm_status["is_granted"]:
        granted_by = perm_status.get('granted_by', 'Admin')
        granted_at = perm_status.get('granted_at', '')[:16]
        st.markdown(f"""
        <div style="background:rgba(75,175,130,0.08);border:1px solid rgba(75,175,130,0.3);
                    border-radius:8px;padding:0.85rem 1.25rem;
                    display:flex;align-items:center;gap:1rem;">
            <span class="ns-pulse-dot"></span>
            <div>
                <div style="font-weight:600;color:{COLOR_SAFE};font-size:0.9rem;">
                    ADMIN CONSENT GRANTED
                </div>
                <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};">
                    Authorized by <strong>{granted_by}</strong> at {granted_at}
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background:rgba(224,82,82,0.08);border:1px solid rgba(224,82,82,0.3);
                    border-radius:8px;padding:0.85rem 1.25rem;
                    display:flex;align-items:center;gap:1rem;">
            <span class="ns-pulse-dot-red"></span>
            <div>
                <div style="font-weight:600;color:{COLOR_CRITICAL};font-size:0.9rem;">
                    ADMIN CONSENT REVOKED
                </div>
                <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};">
                    Live packet scanning is disabled until an ADMIN grants permission.
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

with col_action:
    if is_admin:
        if perm_status["is_granted"]:
            if st.button("⛔  Revoke Permission", use_container_width=True):
                revoke_admin_permission(current_user["username"])
                if realworld_sniffer_engine.is_running():
                    realworld_sniffer_engine.stop_sniffing()
                st.toast("Admin permission REVOKED", icon="⛔")
                st.rerun()
        else:
            if st.button("🔓  Grant Permission", use_container_width=True, type="primary"):
                grant_admin_permission(current_user["username"])
                st.toast("Admin permission GRANTED", icon="✅")
                st.rerun()
    else:
        st.markdown(f"""
        <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};text-align:center;padding:0.5rem;">
            Only ADMIN accounts can modify consent
        </div>
        """, unsafe_allow_html=True)

st.divider()

# ─── Scanner Controls ─────────────────────────────────────────────────────────
if perm_status["is_granted"]:
    section_heading("Network Interface Scanner")

    active_ifaces = list_active_interfaces()

    cs1, cs2, cs3, cs4 = st.columns([2, 1, 1, 1])
    with cs1:
        iface_input = st.selectbox(
            "Active Network Adapter",
            options=active_ifaces,
            label_visibility="collapsed",
            help="Select the network interface to capture from"
        )
    with cs2:
        # Status indicator
        if is_running:
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:0.5rem;padding:0.6rem 0;
                        font-size:0.85rem;font-weight:600;color:{COLOR_SAFE};">
                <span class="ns-pulse-dot"></span> SCANNING LIVE
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="display:flex;align-items:center;gap:0.5rem;padding:0.6rem 0;
                        font-size:0.85rem;color:{COLOR_TEXT_MUTED};">
                <span style="width:8px;height:8px;border-radius:50%;background:{COLOR_TEXT_MUTED};display:inline-block;"></span>
                STOPPED
            </div>
            """, unsafe_allow_html=True)
    with cs3:
        st.metric("Packets Captured", f"{pkt_count:,}")
    with cs4:
        if not is_running:
            if st.button("▶  Start Scanning", disabled=not is_admin, type="primary", use_container_width=True):
                try:
                    realworld_sniffer_engine.callback_fn = realworld_pipeline.handle_realworld_packet
                    realworld_sniffer_engine.start_sniffing(interface=iface_input, user_obj=current_user)
                    st.toast(f"Live scanning started on {iface_input}", icon="▶")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error starting scanner: {e}")
        else:
            if st.button("⏹  Stop Scanning", use_container_width=True):
                realworld_sniffer_engine.stop_sniffing()
                st.toast("Sniffer stopped", icon="⏹")
                st.rerun()

    if not is_admin:
        st.caption("⚠️ Only ADMIN accounts can start/stop live capture.")

    st.divider()

    # ─── Live Feed Tables ─────────────────────────────────────────────────────
    section_heading("Live Packet Feed & Real-Time Alerts")

    auto_refresh = st.checkbox("Auto-refresh every 2 seconds", value=is_running)

    # Filter bar
    f1, f2, f3 = st.columns(3)
    with f1:
        pkt_src_filter = st.text_input("Filter Source IP", placeholder="e.g. 192.168.1.1", label_visibility="collapsed")
    with f2:
        pkt_dst_filter = st.text_input("Filter Dest IP", placeholder="e.g. 10.0.0.1", label_visibility="collapsed")
    with f3:
        pkt_proto_filter = st.selectbox("Protocol", ["ALL", "tcp", "udp", "ip", "icmp"], label_visibility="collapsed")

    recent_pkts  = realtime_bus.get_recent_packets(limit=50)
    recent_alts  = realtime_bus.get_recent_alerts(limit=25)

    col_p, col_a = st.columns([3, 2])

    with col_p:
        pkt_count_live = len(recent_pkts)
        st.markdown(f"""
        <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-bottom:0.5rem;">
            LIVE PACKETS — {pkt_count_live} recent
        </div>
        """, unsafe_allow_html=True)
        if recent_pkts:
            df_pkts = pd.DataFrame(recent_pkts)
            # Apply filters
            if pkt_src_filter:
                df_pkts = df_pkts[df_pkts.get("source_ip", pd.Series(dtype=str)).astype(str).str.contains(pkt_src_filter, na=False)]
            if pkt_dst_filter:
                df_pkts = df_pkts[df_pkts.get("destination_ip", pd.Series(dtype=str)).astype(str).str.contains(pkt_dst_filter, na=False)]
            if pkt_proto_filter != "ALL" and "protocol" in df_pkts.columns:
                df_pkts = df_pkts[df_pkts["protocol"].str.lower() == pkt_proto_filter.lower()]
            st.dataframe(df_pkts, use_container_width=True, hide_index=True, height=320)
        else:
            st.markdown(f"""
            <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                        border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};height:200px;
                        display:flex;align-items:center;justify-content:center;flex-direction:column;">
                <div style="font-size:1.2rem;margin-bottom:0.3rem;">📡</div>
                <div>Waiting for live packets…</div>
                <div style="font-size:0.75rem;margin-top:0.25rem;">Start scanning on a selected interface</div>
            </div>
            """, unsafe_allow_html=True)

    with col_a:
        st.markdown(f"""
        <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-bottom:0.5rem;">
            REAL-TIME ALERTS
        </div>
        """, unsafe_allow_html=True)
        if recent_alts:
            df_alts = pd.DataFrame(recent_alts)
            st.dataframe(df_alts, use_container_width=True, hide_index=True, height=320)
        else:
            st.markdown(f"""
            <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                        border-radius:8px;padding:2rem;text-align:center;color:{COLOR_TEXT_MUTED};height:200px;
                        display:flex;align-items:center;justify-content:center;">
                No anomalies detected
            </div>
            """, unsafe_allow_html=True)

    if auto_refresh and is_running:
        time.sleep(2)
        st.rerun()

else:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🔒</div>
        <div style="font-size:0.9rem;font-weight:500;margin-bottom:0.25rem;">Admin Consent Required</div>
        <div style="font-size:0.8rem;">Grant admin consent above to enable live network scanning.</div>
    </div>
    """, unsafe_allow_html=True)
