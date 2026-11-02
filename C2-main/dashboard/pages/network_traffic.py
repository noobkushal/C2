import streamlit as st
import pandas as pd
from src.database.repositories import get_network_events, get_network_events_count

st.title("🌐 Network Traffic Telemetry")
st.caption("Search, filter, and inspect raw network flow events")

# Filter Sidebar / Controls
with st.expander("🔍 Filter Controls", expanded=True):
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        src_ip = st.text_input("Source IP", value="", placeholder="e.g. 192.168.1.10")
    with c2:
        dst_ip = st.text_input("Destination IP", value="", placeholder="e.g. 10.0.0.1")
    with c3:
        protocol_select = st.multiselect("Protocol", options=["tcp", "udp", "icmp"], default=[])
    with c4:
        domain_search = st.text_input("Domain Search", value="", placeholder="e.g. example.com")

    c5, c6 = st.columns(2)
    with c5:
        port_range = st.slider("Destination Port Range", min_value=1, max_value=65535, value=(1, 65535))
    with c6:
        log_src_select = st.selectbox("Log Source", options=["ALL", "conn", "http", "ssl", "dns", "simulation"])

# Pagination controls
cp1, cp2, cp3 = st.columns([1, 2, 1])
with cp1:
    page_size = st.selectbox("Page Size", options=[25, 50, 100, 200], index=1)
if "net_page_num" not in st.session_state:
    st.session_state["net_page_num"] = 1

min_p = port_range[0] if port_range[0] > 1 else None
max_p = port_range[1] if port_range[1] < 65535 else None
log_src = log_src_select if log_src_select != "ALL" else None

total_count = get_network_events_count(
    source_ip=src_ip or None,
    destination_ip=dst_ip or None,
    protocol=protocol_select or None
)

max_pages = max(1, (total_count + page_size - 1) // page_size)
if st.session_state["net_page_num"] > max_pages:
    st.session_state["net_page_num"] = max_pages

with cp2:
    st.markdown(f"<div style='text-align:center; padding-top:10px;'>Page {st.session_state['net_page_num']} of {max_pages} ({total_count:,} total records)</div>", unsafe_allow_html=True)
with cp3:
    btn_prev, btn_next = st.columns(2)
    if btn_prev.button("◀ Prev", disabled=(st.session_state["net_page_num"] <= 1)):
        st.session_state["net_page_num"] -= 1
        st.rerun()
    if btn_next.button("Next ▶", disabled=(st.session_state["net_page_num"] >= max_pages)):
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
    offset=offset
)

if not events_df.empty:
    cols = ["timestamp", "source_ip", "source_port", "destination_ip", "destination_port", "protocol", "domain", "duration", "bytes_sent", "bytes_received", "connection_state", "log_source", "pcap_reference"]
    display_df = events_df[[c for c in cols if c in events_df.columns]]
    st.dataframe(display_df, use_container_width=True, hide_index=True)
else:
    st.info("No network events found matching the specified filters.")
