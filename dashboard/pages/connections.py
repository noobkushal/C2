import streamlit as st
import plotly.express as px
import pandas as pd
from src.database.repositories import get_network_events
from src.detection.connection_frequency import (
    connections_per_source,
    connections_per_destination,
    connections_per_minute,
    flag_high_frequency
)
from dashboard.theme import COLOR_LOW, COLOR_HIGH, COLOR_SAFE

st.title("⚡ Connection Frequency & Burst Analytics")
st.caption("Inspect connection rates, high-frequency spikes, and chatter volume across hosts")

events_df = get_network_events(limit=10000)

if events_df.empty:
    st.info("No network events found in database.")
    st.stop()

col1, col2 = st.columns(2)

with col1:
    st.subheader("Top Talkers (Source IPs)")
    src_map = connections_per_source(events_df)
    src_df = pd.DataFrame(list(src_map.items()), columns=["Source IP", "Connections"]).sort_values("Connections", ascending=False).head(10)
    fig_src = px.bar(src_df, x="Connections", y="Source IP", orientation="h", color_discrete_sequence=[COLOR_LOW])
    fig_src.update_layout(yaxis=dict(autorange="reversed"), height=300)
    st.plotly_chart(fig_src, use_container_width=True)

with col2:
    st.subheader("Most Contacted (Destination IPs)")
    dst_map = connections_per_destination(events_df)
    dst_df = pd.DataFrame(list(dst_map.items()), columns=["Destination IP", "Connections"]).sort_values("Connections", ascending=False).head(10)
    fig_dst = px.bar(dst_df, x="Connections", y="Destination IP", orientation="h", color_discrete_sequence=[COLOR_SAFE])
    fig_dst.update_layout(yaxis=dict(autorange="reversed"), height=300)
    st.plotly_chart(fig_dst, use_container_width=True)

st.divider()
st.subheader("📊 Connection Burst Rate Visualizer")

pairs_df = events_df.groupby(["source_ip", "destination_ip"]).size().reset_index(name="count").sort_values("count", ascending=False)
pair_options = [f"{r['source_ip']} -> {r['destination_ip']} ({r['count']} conns)" for _, r in pairs_df.iterrows()]

selected_pair = st.selectbox("Select (Source -> Destination) Pair", pair_options)
if selected_pair:
    parts = selected_pair.split(" -> ")
    s_ip = parts[0].strip()
    d_ip = parts[1].split(" (")[0].strip()
    
    rate_series = connections_per_minute(events_df, source_ip=s_ip, destination_ip=d_ip)
    if not rate_series.empty:
        rate_df = rate_series.reset_index(name="connections_per_min")
        fig_rate = px.line(
            rate_df, x="dt", y="connections_per_min",
            title=f"1-Minute Connection Rate for {s_ip} -> {d_ip}",
            labels={"dt": "Time (UTC)", "connections_per_min": "Connections / Min"},
            color_discrete_sequence=[COLOR_HIGH]
        )
        fig_rate.update_layout(height=300)
        st.plotly_chart(fig_rate, use_container_width=True)
