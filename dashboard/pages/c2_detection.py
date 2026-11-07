import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.database.repositories import get_network_events
from src.detection.beacon_detection import detect_beaconing, calculate_group_beacon_stats
from src.detection.rare_destination import compute_destination_frequency, flag_rare_destinations
from dashboard.theme import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE, COLOR_ACCENT,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_TEXT, COLOR_TEXT_MUTED,
    render_page_header, render_severity_badge, section_heading
)

render_page_header(
    "C2 Beaconing Analytics",
    "Statistical interval variance detection for command-and-control beaconing behavior",
    "📡"
)

events_df = get_network_events(limit=10000)

if events_df.empty:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">📡</div>
        <div>No network events available to analyze for beaconing.</div>
        <div style="font-size:0.8rem;margin-top:0.25rem;">Generate sample data from Settings to populate the database.</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Run detection ────────────────────────────────────────────────────────────
with st.spinner("Running beacon analysis…"):
    dest_freq   = compute_destination_frequency(events_df)
    rare_dsts   = flag_rare_destinations(dest_freq, events_df=events_df)
    candidates  = detect_beaconing(events_df, rare_destinations=rare_dsts)

# ─── KPIs ─────────────────────────────────────────────────────────────────────
k1, k2, k3, k4 = st.columns(4)
with k1:
    st.metric("Events Analyzed",     f"{len(events_df):,}")
with k2:
    st.metric("Beacon Candidates",   f"{len(candidates):,}")
with k3:
    if candidates:
        high_conf = sum(1 for c in candidates if c.get("beacon_score", 0) >= 70)
        st.metric("High Confidence",  f"{high_conf:,}")
    else:
        st.metric("High Confidence",  "0")
with k4:
    if candidates:
        best_cv = min(c.get("cv", 1) for c in candidates)
        st.metric("Best CV (lowest)", f"{best_cv:.4f}")
    else:
        st.metric("Best CV (lowest)", "N/A")

if not candidates:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:2rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:1rem 0;">
        No candidate beaconing pairs found (min_connections threshold not met).
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Candidates table ─────────────────────────────────────────────────────────
section_heading("Beaconing Candidate Pairs")

cand_df = pd.DataFrame(candidates)
disp_cols = ["source_ip", "destination_ip", "destination_port",
             "connection_count", "mean_interval", "stdev_interval", "cv",
             "conns_per_hour", "beacon_score"]
available_cols = [c for c in disp_cols if c in cand_df.columns]
cand_display   = cand_df[available_cols].copy()
col_renames = {
    "source_ip": "Source IP", "destination_ip": "Destination IP",
    "destination_port": "Port", "connection_count": "Connections",
    "mean_interval": "Avg Interval (s)", "stdev_interval": "Std Dev (s)",
    "cv": "CV", "conns_per_hour": "Conns/Hr", "beacon_score": "Risk Score"
}
cand_display.columns = [col_renames.get(c, c) for c in available_cols]
st.dataframe(cand_display, use_container_width=True, hide_index=True)

st.divider()

# ─── Detailed visualizer ─────────────────────────────────────────────────────
section_heading("Beacon Interval Regularity Visualizer")

selected_cand_idx = st.selectbox(
    "Select Candidate Pair",
    options=list(range(len(candidates))),
    format_func=lambda i: (
        f"{candidates[i]['source_ip']} → {candidates[i]['destination_ip']}:{candidates[i]['destination_port']} "
        f"(CV={candidates[i]['cv']:.4f}, Score={candidates[i]['beacon_score']})"
    )
)

cand = candidates[selected_cand_idx]
c_events = events_df[
    (events_df["source_ip"] == cand["source_ip"]) &
    (events_df["destination_ip"] == cand["destination_ip"]) &
    (events_df["destination_port"] == cand["destination_port"])
].copy()

if not c_events.empty:
    c_events["dt"] = pd.to_datetime(c_events["timestamp"], errors="coerce")
    c_events = c_events.dropna(subset=["dt"]).sort_values("dt")

    # Beacon metadata
    m1, m2, m3, m4, m5 = st.columns(5)
    stats = calculate_group_beacon_stats(c_events["timestamp"].tolist())
    with m1: st.metric("Connections",     stats["connection_count"])
    with m2: st.metric("Mean Interval",   f"{stats['mean']:.2f}s")
    with m3: st.metric("Std Deviation",   f"{stats['stdev']:.2f}s")
    with m4: st.metric("CV",              f"{stats['cv']:.4f}" if stats['cv'] is not None else "N/A")
    with m5:
        cv_val = stats['cv'] or 1.0
        if cv_val < 0.1:
            conf_label = "🔴 HIGH"
        elif cv_val < 0.25:
            conf_label = "🟠 MEDIUM"
        else:
            conf_label = "🟡 LOW"
        st.metric("Beacon Confidence", conf_label)

    col1, col2 = st.columns(2)

    with col1:
        section_heading("Connection Pulse Timeline")
        fig_scatter = go.Figure()
        fig_scatter.add_trace(go.Scatter(
            x=c_events["dt"],
            y=[1] * len(c_events),
            mode="markers",
            marker=dict(
                size=14, symbol="line-ns",
                color=COLOR_HIGH,
                line=dict(width=3, color=COLOR_CRITICAL)
            ),
            hovertemplate="<b>%{x}</b><extra></extra>",
            name="Connection"
        ))
        fig_scatter.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE,
            plot_bgcolor=COLOR_SURFACE,
            yaxis=dict(showticklabels=False, range=[0.5, 1.5]),
            xaxis_title="Timestamp (UTC)",
            showlegend=False,
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    with col2:
        section_heading("Inter-Arrival Time Distribution")
        intervals = stats.get("intervals", [])
        if intervals:
            fig_hist = px.histogram(
                x=intervals, nbins=15,
                labels={"x": "Interval Duration (seconds)", "count": "Frequency"},
                color_discrete_sequence=[COLOR_LOW],
            )
            fig_hist.add_vline(
                x=stats['mean'], line_dash="dash",
                line_color=COLOR_ACCENT, annotation_text=f"Mean: {stats['mean']:.1f}s"
            )
            fig_hist.update_layout(
                height=280,
                margin=dict(l=10, r=10, t=10, b=20),
                paper_bgcolor=COLOR_SURFACE,
                plot_bgcolor=COLOR_SURFACE,
            )
            st.plotly_chart(fig_hist, use_container_width=True)
        else:
            st.info("Insufficient intervals to plot histogram.")

    # Rare destination context
    if rare_dsts:
        is_rare = cand["destination_ip"] in [r.get("destination_ip") for r in rare_dsts]
        if is_rare:
            st.markdown(f"""
            <div style="background:rgba(216,137,85,0.08);border:1px solid rgba(216,137,85,0.3);
                        border-radius:6px;padding:0.75rem 1rem;margin-top:0.5rem;font-size:0.83rem;">
                ⚠️ <strong style="color:{COLOR_HIGH};">Rare Destination</strong> — 
                <code>{cand['destination_ip']}</code> is contacted by a low percentage of hosts
            </div>
            """, unsafe_allow_html=True)
