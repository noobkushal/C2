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
from dashboard.theme import (
    COLOR_LOW, COLOR_HIGH, COLOR_SAFE, COLOR_ACCENT, COLOR_MEDIUM, COLOR_CRITICAL,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_TEXT, COLOR_TEXT_MUTED,
    render_page_header, section_heading
)

render_page_header(
    "Connection Frequency & Burst Analytics",
    "Connection rates, high-frequency spikes, and chatter volume across hosts",
    "⚡"
)

events_df = get_network_events(limit=10000)

if events_df.empty:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">⚡</div>
        No network events found. Generate sample data from Settings.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── KPIs ─────────────────────────────────────────────────────────────────────
src_map  = connections_per_source(events_df)
dst_map  = connections_per_destination(events_df)
hf_flags = flag_high_frequency(events_df)

k1, k2, k3, k4 = st.columns(4)
with k1: st.metric("Total Events",       f"{len(events_df):,}")
with k2: st.metric("Unique Source IPs",  f"{len(src_map):,}")
with k3: st.metric("Unique Dest IPs",    f"{len(dst_map):,}")
with k4: st.metric("High-Freq Sources",  f"{len(hf_flags):,}")

st.divider()

# ─── Top talkers charts ────────────────────────────────────────────────────────
col1, col2 = st.columns(2)

with col1:
    section_heading("Top Talkers (Source IPs)")
    src_df = (pd.DataFrame(list(src_map.items()), columns=["Source IP", "Connections"])
              .sort_values("Connections", ascending=False).head(15))
    fig_src = px.bar(
        src_df, x="Connections", y="Source IP", orientation="h",
        color_discrete_sequence=[COLOR_LOW],
    )
    # Highlight high-frequency sources
    hf_ips = set(f.get("source_ip", "") for f in hf_flags)
    bar_colors = [COLOR_CRITICAL if ip in hf_ips else COLOR_LOW for ip in src_df["Source IP"]]
    fig_src.update_traces(marker_color=bar_colors)
    fig_src.update_layout(
        yaxis=dict(autorange="reversed"),
        height=380,
        margin=dict(l=10, r=10, t=10, b=20),
        paper_bgcolor=COLOR_SURFACE,
        plot_bgcolor=COLOR_SURFACE,
    )
    st.plotly_chart(fig_src, use_container_width=True)
    if hf_ips:
        st.markdown(f"""
        <div style="font-size:0.75rem;color:{COLOR_CRITICAL};margin-top:-0.5rem;">
            🔴 Red bars = high-frequency sources
        </div>
        """, unsafe_allow_html=True)

with col2:
    section_heading("Most Contacted (Destination IPs)")
    dst_df = (pd.DataFrame(list(dst_map.items()), columns=["Destination IP", "Connections"])
              .sort_values("Connections", ascending=False).head(15))
    fig_dst = px.bar(
        dst_df, x="Connections", y="Destination IP", orientation="h",
        color_discrete_sequence=[COLOR_SAFE],
    )
    fig_dst.update_layout(
        yaxis=dict(autorange="reversed"),
        height=380,
        margin=dict(l=10, r=10, t=10, b=20),
        paper_bgcolor=COLOR_SURFACE,
        plot_bgcolor=COLOR_SURFACE,
    )
    st.plotly_chart(fig_dst, use_container_width=True)

st.divider()

# ─── High-frequency flags table ────────────────────────────────────────────────
if hf_flags:
    section_heading("High-Frequency Connection Flags")
    hf_df = pd.DataFrame(hf_flags)
    st.dataframe(hf_df, use_container_width=True, hide_index=True)
    st.divider()

# ─── Connection burst rate visualizer ─────────────────────────────────────────
section_heading("Connection Burst Rate — Pair Analysis")

pairs_df = (events_df.groupby(["source_ip", "destination_ip"])
            .size().reset_index(name="count")
            .sort_values("count", ascending=False))
pair_options = [
    f"{r['source_ip']} → {r['destination_ip']} ({r['count']} conns)"
    for _, r in pairs_df.iterrows()
]

if pair_options:
    selected_pair = st.selectbox("Select Source → Destination Pair", pair_options)
    if selected_pair:
        parts  = selected_pair.split(" → ")
        s_ip   = parts[0].strip()
        d_ip   = parts[1].split(" (")[0].strip()

        rate_series = connections_per_minute(events_df, source_ip=s_ip, destination_ip=d_ip)
        if not rate_series.empty:
            rate_df = rate_series.reset_index(name="connections_per_min")
            fig_rate = px.line(
                rate_df, x="dt", y="connections_per_min",
                labels={"dt": "Time (UTC)", "connections_per_min": "Connections / Min"},
                color_discrete_sequence=[COLOR_HIGH],
            )
            fig_rate.update_traces(
                line=dict(width=2),
                fill="tozeroy",
                fillcolor="rgba(216,137,85,0.06)"
            )
            # Add threshold line
            try:
                from src.utils.config_loader import load_detection_rules
                rules_cfg = load_detection_rules()
                threshold = rules_cfg["connection_frequency"]["threshold_per_minute"]
                fig_rate.add_hline(
                    y=threshold, line_dash="dash",
                    line_color=COLOR_CRITICAL,
                    annotation_text=f"Alert threshold: {threshold}"
                )
            except Exception:
                pass
            fig_rate.update_layout(
                height=300,
                margin=dict(l=10, r=10, t=20, b=20),
                paper_bgcolor=COLOR_SURFACE,
                plot_bgcolor=COLOR_SURFACE,
            )
            st.plotly_chart(fig_rate, use_container_width=True)
        else:
            st.info("No time-series data available for this pair.")
else:
    st.info("No connection pairs found.")
