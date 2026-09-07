import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.database.repositories import (
    get_overview_kpis,
    get_alerts,
    get_network_events
)
from dashboard.theme import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE,
    COLOR_CANVAS, COLOR_SURFACE, COLOR_BORDER_SUBTLE
)

st.title("📊 Security Operations Overview")
st.caption("Real-time telemetry and active threat metrics")

try:
    kpis = get_overview_kpis()
except Exception as e:
    st.error(f"Error loading overview KPIs: {e}")
    st.stop()

# 6 Metric KPI Cards
c1, c2, c3, c4, c5, c6 = st.columns(6)
with c1:
    st.metric("Network Events", f"{kpis['network_events']:,}")
with c2:
    st.metric("Active Alerts", f"{kpis['active_alerts']:,}")
with c3:
    st.metric("High/Critical", f"{kpis['high_critical_alerts']:,}")
with c4:
    st.metric("C2 Beacons", f"{kpis['beacon_alerts']:,}")
with c5:
    st.metric("Unique Dsts", f"{kpis['unique_destinations']:,}")
with c6:
    st.metric("DNS Queries", f"{kpis['dns_queries']:,}")

st.divider()

col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Network Event Activity Timeline")
    events_df = get_network_events(limit=5000)
    if not events_df.empty:
        events_df["dt"] = pd.to_datetime(events_df["timestamp"])
        resampled = events_df.set_index("dt").resample("5min").size().reset_index(name="event_count")
        
        fig_timeline = px.line(
            resampled, x="dt", y="event_count",
            labels={"dt": "Time (UTC)", "event_count": "Event Volume"},
            title="Event Volume over Time (5m buckets)"
        )
        fig_timeline.update_traces(line_color=COLOR_LOW, line_width=2)
        fig_timeline.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=300)
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No network events captured yet. Run the pipeline or load sample data from Settings.")

with col_right:
    st.subheader("Alert Severity Breakdown")
    alerts_df = get_alerts(limit=1000)
    if not alerts_df.empty:
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]
        
        color_map = {"CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH, "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW}
        fig_donut = px.pie(
            sev_counts, names="severity", values="count",
            color="severity", color_discrete_map=color_map,
            hole=0.45, title="Active Alert Distribution"
        )
        fig_donut.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=300)
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        st.info("No active alerts generated yet.")

col_b1, col_b2 = st.columns(2)

with col_b1:
    st.subheader("Top 10 Destination IPs")
    if not events_df.empty:
        top_dsts = events_df["destination_ip"].value_counts().head(10).reset_index()
        top_dsts.columns = ["destination_ip", "connections"]
        fig_dsts = px.bar(
            top_dsts, x="connections", y="destination_ip", orientation="h",
            color_discrete_sequence=[COLOR_SAFE],
            labels={"connections": "Connections", "destination_ip": "Destination IP"}
        )
        fig_dsts.update_layout(yaxis=dict(autorange="reversed"), height=300, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_dsts, use_container_width=True)
    else:
        st.info("No event data available.")

with col_b2:
    st.subheader("Top Network Protocols")
    if not events_df.empty:
        proto_counts = events_df["protocol"].fillna("unknown").value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]
        fig_proto = px.bar(
            proto_counts, x="protocol", y="count",
            color_discrete_sequence=[COLOR_LOW],
            labels={"count": "Event Count", "protocol": "Protocol"}
        )
        fig_proto.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_proto, use_container_width=True)
    else:
        st.info("No protocol data available.")

st.divider()
st.subheader("🚨 Recent High-Risk Alerts")

recent_alerts = get_alerts(limit=10)
if not recent_alerts.empty:
    display_df = recent_alerts[["alert_id", "last_seen", "alert_type", "source_ip", "destination_ip", "destination_port", "severity", "risk_score", "status", "reason"]].copy()
    st.dataframe(display_df, use_container_width=True, hide_index=True)
else:
    st.info("No alerts logged in the system.")
