import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.database.repositories import get_network_events
from src.detection.beacon_detection import detect_beaconing, calculate_group_beacon_stats
from src.detection.rare_destination import compute_destination_frequency, flag_rare_destinations
from dashboard.theme import COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE

st.title("📡 C2 Beaconing Analytics & Regularity Analyzer")
st.caption("Statistical interval variance detection for beaconing command-and-control behavior")

events_df = get_network_events(limit=10000)

if events_df.empty:
    st.info("No network events available to analyze for beaconing.")
    st.stop()

# Compute rare destinations to feed detector
dest_freq = compute_destination_frequency(events_df)
rare_dsts = flag_rare_destinations(dest_freq, events_df=events_df)

candidates = detect_beaconing(events_df, rare_destinations=rare_dsts)

if not candidates:
    st.info("No candidate beaconing pairs found meeting min_connections threshold (default 4).")
    st.stop()

cand_df = pd.DataFrame(candidates)
disp_cols = ["source_ip", "destination_ip", "destination_port", "connection_count", "mean_interval", "stdev_interval", "cv", "conns_per_hour", "beacon_score"]
cand_display = cand_df[disp_cols].copy()
cand_display.columns = ["Source IP", "Destination IP", "Port", "Connections", "Avg Interval (s)", "Deviation (s)", "CV", "Conns/Hr", "Risk Score"]

st.subheader("Beaconing Candidate Pairs")
st.dataframe(cand_display, use_container_width=True, hide_index=True)

st.divider()
st.subheader("📈 Beacon Interval Regularity Visualizer")

selected_cand_idx = st.selectbox(
    "Select Candidate Pair to Visualize",
    options=list(range(len(candidates))),
    format_func=lambda i: f"{candidates[i]['source_ip']} -> {candidates[i]['destination_ip']}:{candidates[i]['destination_port']} (CV={candidates[i]['cv']:.4f}, Score={candidates[i]['beacon_score']})"
)

cand = candidates[selected_cand_idx]
c_events = events_df[
    (events_df["source_ip"] == cand["source_ip"]) &
    (events_df["destination_ip"] == cand["destination_ip"]) &
    (events_df["destination_port"] == cand["destination_port"])
].copy()

if not c_events.empty:
    c_events["dt"] = pd.to_datetime(c_events["timestamp"])
    c_events = c_events.sort_values("dt")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("##### Connection Pulse Timeline")
        fig_scatter = go.Figure()
        fig_scatter.add_trace(go.Scatter(
            x=c_events["dt"],
            y=[1] * len(c_events),
            mode="markers",
            marker=dict(size=12, color=COLOR_HIGH, symbol="line-ns", line=dict(width=3, color=COLOR_CRITICAL)),
            hoverinfo="x"
        ))
        fig_scatter.update_layout(
            yaxis=dict(showticklabels=False, range=[0.5, 1.5]),
            xaxis_title="Timestamp (UTC)",
            height=260,
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig_scatter, use_container_width=True)
        
    with col2:
        st.write("##### Inter-Arrival Time Distribution (Histogram)")
        stats = calculate_group_beacon_stats(c_events["timestamp"].tolist())
        intervals = stats["intervals"]
        
        if intervals:
            fig_hist = px.histogram(
                x=intervals, nbins=15,
                labels={"x": "Interval Duration (seconds)"},
                title="Interval Distribution",
                color_discrete_sequence=[COLOR_LOW]
            )
            fig_hist.update_layout(height=260, margin=dict(l=20, r=20, t=30, b=20))
            st.plotly_chart(fig_hist, use_container_width=True)
        else:
            st.info("Insufficient intervals to plot histogram.")
