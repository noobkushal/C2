import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.database.repositories import get_network_events, get_network_events_count
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_LOW,
    COLOR_SAFE, COLOR_HIGH, COLOR_MEDIUM, COLOR_CRITICAL,
    render_page_header, section_heading
)

render_page_header(
    "Network Traffic Telemetry",
    "Search, filter, and inspect raw network flow events with paginated views",
    "🌐"
)

# ─── Filters ──────────────────────────────────────────────────────────────────
with st.expander("🔍  Filter Controls", expanded=True):
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        src_ip = st.text_input("Source IP", placeholder="e.g. 192.168.1.10")
    with c2:
        dst_ip = st.text_input("Destination IP", placeholder="e.g. 10.0.0.1")
    with c3:
        protocol_select = st.multiselect("Protocol", options=["tcp", "udp", "icmp"], default=[])
    with c4:
        domain_search = st.text_input("Domain", placeholder="e.g. example.com")

    c5, c6 = st.columns(2)
    with c5:
        port_range = st.slider("Destination Port Range", 1, 65535, (1, 65535))
    with c6:
        log_src_select = st.selectbox("Log Source", ["ALL", "conn", "http", "ssl", "dns", "simulation", "realworld_nic", "socket_raw"])

# ─── Pagination controls ──────────────────────────────────────────────────────
if "net_page_num" not in st.session_state:
    st.session_state["net_page_num"] = 1

min_p    = port_range[0] if port_range[0] > 1     else None
max_p    = port_range[1] if port_range[1] < 65535  else None
log_src  = log_src_select if log_src_select != "ALL" else None

total_count = get_network_events_count(
    source_ip=src_ip or None,
    destination_ip=dst_ip or None,
    protocol=protocol_select or None,
)

page_size = 50
max_pages = max(1, (total_count + page_size - 1) // page_size)
if st.session_state["net_page_num"] > max_pages:
    st.session_state["net_page_num"] = max_pages

pg_col1, pg_col2, pg_col3 = st.columns([2, 4, 2])
with pg_col1:
    st.markdown(f"""
    <div style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};padding:0.6rem 0;">
        <strong style="color:{COLOR_TEXT};">{total_count:,}</strong> total records
    </div>
    """, unsafe_allow_html=True)
with pg_col2:
    st.markdown(f"""
    <div style="text-align:center;font-size:0.82rem;color:{COLOR_TEXT_MUTED};padding:0.6rem 0;">
        Page <strong style="color:{COLOR_TEXT};">{st.session_state['net_page_num']}</strong> of {max_pages}
    </div>
    """, unsafe_allow_html=True)
with pg_col3:
    bp, bn = st.columns(2)
    if bp.button("◀ Prev", disabled=(st.session_state["net_page_num"] <= 1), use_container_width=True):
        st.session_state["net_page_num"] -= 1
        st.rerun()
    if bn.button("Next ▶", disabled=(st.session_state["net_page_num"] >= max_pages), use_container_width=True):
        st.session_state["net_page_num"] += 1
        st.rerun()

offset = (st.session_state["net_page_num"] - 1) * page_size

events_df = get_network_events(
    source_ip=src_ip or None,
    destination_ip=dst_ip or None,
    protocol=protocol_select or None,
    min_port=min_p,
    max_port=max_p,
    domain=domain_search or None,
    log_source=log_src,
    limit=page_size,
    offset=offset,
)

if not events_df.empty:
    display_cols = ["timestamp", "source_ip", "source_port", "destination_ip",
                    "destination_port", "protocol", "domain", "duration",
                    "bytes_sent", "bytes_received", "connection_state", "log_source"]
    display_df = events_df[[c for c in display_cols if c in events_df.columns]]
    st.dataframe(display_df, use_container_width=True, hide_index=True, height=450)
else:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};">
        <div style="font-size:1.2rem;margin-bottom:0.3rem;">🌐</div>
        No network events match the selected filters.
    </div>
    """, unsafe_allow_html=True)

# ─── Protocol chart ───────────────────────────────────────────────────────────
if not events_df.empty:
    st.divider()
    section_heading("Protocol Distribution (Current Page)")
    proto_counts = events_df["protocol"].fillna("unknown").value_counts().reset_index()
    proto_counts.columns = ["protocol", "count"]
    fig = px.pie(
        proto_counts, names="protocol", values="count",
        color_discrete_sequence=[COLOR_ACCENT, COLOR_LOW, COLOR_SAFE, COLOR_MEDIUM],
        hole=0.5,
    )
    fig.update_layout(
        height=220,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor=COLOR_SURFACE,
        showlegend=True,
    )
    col_chart, col_stats = st.columns([2, 1])
    with col_chart:
        st.plotly_chart(fig, use_container_width=True)
    with col_stats:
        section_heading("Page Stats")
        st.metric("Events (Page)", len(events_df))
        st.metric("Unique Src IPs",  events_df["source_ip"].nunique())
        st.metric("Unique Dst IPs",  events_df["destination_ip"].nunique())
        avg_bytes = events_df["bytes_sent"].mean() if "bytes_sent" in events_df.columns else 0
        st.metric("Avg Bytes Sent",  f"{avg_bytes:.0f}")
