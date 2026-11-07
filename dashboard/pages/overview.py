import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.database.repositories import (
    get_overview_kpis,
    get_alerts,
    get_network_events
)
from src.services.auth_service import verify_session
from dashboard.theme import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE,
    COLOR_BG, COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_ACCENT,
    COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED, COLOR_BORDER,
    render_page_header, render_sensor_banner, render_severity_badge,
    render_status_badge, section_heading
)

# ─── Auth check ───────────────────────────────────────────────────────────────
current_user = verify_session(st.session_state.get("session_token")) if st.session_state.get("session_token") else None

# ─── Auto-refresh control ──────────────────────────────────────────────────────
import time as _time

_refresh_options = {"Off": 0, "30s": 30, "1 min": 60, "5 min": 300}
_hdr_col, _ref_col = st.columns([5, 1])
with _hdr_col:
    render_page_header("Security Operations Overview", "Real-time telemetry, active threats, and platform health", "📊")
with _ref_col:
    st.markdown("<div style='padding-top:1.1rem;'></div>", unsafe_allow_html=True)
    _refresh_label = st.selectbox(
        "Auto-refresh",
        list(_refresh_options.keys()),
        index=0,
        key="overview_refresh_interval",
        label_visibility="collapsed",
        help="Auto-refresh interval for this page"
    )
_refresh_secs = _refresh_options[_refresh_label]

# ─── Sensor status banner ─────────────────────────────────────────────────────
try:
    from src.ingestion.realworld_sniffer import realworld_sniffer_engine
    sensor_active = realworld_sniffer_engine.is_running()
    pkt_count     = realworld_sniffer_engine.packets_captured_count
    details       = f"{pkt_count:,} packets captured this session" if sensor_active else ""
except Exception:
    sensor_active = False
    details       = ""

render_sensor_banner(sensor_active, "NetSentry Local Agent", details)

# ─── Load KPIs ────────────────────────────────────────────────────────────────
try:
    kpis = get_overview_kpis()
except Exception as e:
    st.error(f"Error loading overview KPIs: {e}")
    st.stop()

# ─── KPI Grid — Row 1 (4 cards) ──────────────────────────────────────────────
section_heading("Key Performance Indicators")

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.metric("Network Events", f"{kpis['network_events']:,}", delta=None)
with c2:
    active = kpis['active_alerts']
    st.metric("Active Alerts", f"{active:,}")
with c3:
    hc = kpis['high_critical_alerts']
    st.metric("High / Critical", f"{hc:,}")
with c4:
    st.metric("C2 Beacon Alerts", f"{kpis['beacon_alerts']:,}")

# ─── KPI Grid — Row 2 (4 cards) ──────────────────────────────────────────────
c5, c6, c7, c8 = st.columns(4)
with c5:
    st.metric("Unique Destinations", f"{kpis['unique_destinations']:,}")
with c6:
    st.metric("DNS Queries", f"{kpis['dns_queries']:,}")
with c7:
    # Compute investigations count
    try:
        from src.database.database import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM investigations")
        inv_count = cur.fetchone()[0]
        conn.close()
    except Exception:
        inv_count = 0
    st.metric("Active Investigations", f"{inv_count:,}")
with c8:
    # Compute false positive count
    try:
        fp_alerts = get_alerts(status="FALSE_POSITIVE", limit=1)
        conn2 = get_db_connection()
        cur2 = conn2.cursor()
        cur2.execute("SELECT COUNT(*) FROM alerts WHERE status='FALSE_POSITIVE'")
        fp_count = cur2.fetchone()[0]
        conn2.close()
    except Exception:
        fp_count = 0
    st.metric("False Positives", f"{fp_count:,}")

st.divider()

# ─── Charts Row 1 ─────────────────────────────────────────────────────────────
col_left, col_right = st.columns([2, 1])

with col_left:
    section_heading("Network Event Activity Timeline (5-min buckets)")
    events_df = get_network_events(limit=8000)
    if not events_df.empty:
        events_df["dt"] = pd.to_datetime(events_df["timestamp"], errors="coerce")
        events_df = events_df.dropna(subset=["dt"])
        resampled = events_df.set_index("dt").resample("5min").size().reset_index(name="event_count")

        fig_timeline = go.Figure()
        fig_timeline.add_trace(go.Scatter(
            x=resampled["dt"],
            y=resampled["event_count"],
            mode="lines",
            line=dict(color=COLOR_ACCENT, width=2.5),
            fill="tozeroy",
            fillcolor=f"rgba(216,137,85,0.08)",
            hovertemplate="<b>%{x}</b><br>Events: %{y}<extra></extra>"
        ))
        fig_timeline.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=20),
            paper_bgcolor=COLOR_SURFACE,
            plot_bgcolor=COLOR_SURFACE,
            xaxis=dict(gridcolor=COLOR_BORDER_SUBTLE, tickfont=dict(size=11)),
            yaxis=dict(gridcolor=COLOR_BORDER_SUBTLE, tickfont=dict(size=11)),
            showlegend=False,
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                    border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};height:280px;
                    display:flex;align-items:center;justify-content:center;flex-direction:column;">
            <div style="font-size:1.5rem;margin-bottom:0.5rem;">📊</div>
            <div style="font-size:0.88rem;">No events captured yet</div>
            <div style="font-size:0.75rem;margin-top:0.25rem;">Load sample data from Settings →</div>
        </div>
        """, unsafe_allow_html=True)

with col_right:
    section_heading("Alert Severity Distribution")
    alerts_df = get_alerts(limit=2000)
    if not alerts_df.empty:
        sev_counts = alerts_df["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]

        color_map = {
            "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
        }
        fig_donut = px.pie(
            sev_counts, names="severity", values="count",
            color="severity", color_discrete_map=color_map,
            hole=0.55,
        )
        fig_donut.update_traces(
            textposition="outside",
            textinfo="label+percent",
            textfont=dict(size=11),
        )
        fig_donut.update_layout(
            height=280,
            margin=dict(l=10, r=10, t=20, b=20),
            paper_bgcolor=COLOR_SURFACE,
            showlegend=False,
        )
        st.plotly_chart(fig_donut, use_container_width=True)
    else:
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                    border-radius:8px;padding:2rem;text-align:center;color:{COLOR_TEXT_MUTED};height:280px;
                    display:flex;align-items:center;justify-content:center;">
            No alert data
        </div>
        """, unsafe_allow_html=True)

# ─── Charts Row 2 ─────────────────────────────────────────────────────────────
col_b1, col_b2 = st.columns(2)

with col_b1:
    section_heading("Top 10 Destination IPs")
    if not events_df.empty:
        top_dsts = events_df["destination_ip"].value_counts().head(10).reset_index()
        top_dsts.columns = ["destination_ip", "connections"]
        fig_dsts = px.bar(
            top_dsts, x="connections", y="destination_ip", orientation="h",
            color_discrete_sequence=[COLOR_LOW],
            labels={"connections": "Connections", "destination_ip": "IP Address"},
        )
        fig_dsts.update_traces(
            marker_color=[COLOR_ACCENT if i == 0 else COLOR_LOW for i in range(len(top_dsts))],
        )
        fig_dsts.update_layout(
            yaxis=dict(autorange="reversed"),
            height=300,
            margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE,
            plot_bgcolor=COLOR_SURFACE,
        )
        st.plotly_chart(fig_dsts, use_container_width=True)
    else:
        st.info("No event data available.")

with col_b2:
    section_heading("Protocol Distribution")
    if not events_df.empty:
        proto_counts = events_df["protocol"].fillna("unknown").value_counts().reset_index()
        proto_counts.columns = ["protocol", "count"]
        proto_colors = [COLOR_ACCENT, COLOR_LOW, COLOR_SAFE, COLOR_MEDIUM, COLOR_HIGH]
        fig_proto = px.bar(
            proto_counts, x="protocol", y="count",
            color="protocol",
            color_discrete_sequence=proto_colors,
            labels={"count": "Event Count", "protocol": "Protocol"},
        )
        fig_proto.update_layout(
            height=300,
            margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE,
            plot_bgcolor=COLOR_SURFACE,
            showlegend=False,
        )
        st.plotly_chart(fig_proto, use_container_width=True)
    else:
        st.info("No protocol data available.")

# ─── Recent High-Risk Alerts table ────────────────────────────────────────────
st.divider()
section_heading("Recent High-Risk Alerts")

recent_alerts = get_alerts(limit=15)
if not recent_alerts.empty:
    # Render styled cards instead of plain dataframe
    for _, row in recent_alerts.head(8).iterrows():
        sev = row['severity'].upper()
        sev_color_map = {
            "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
        }
        left_border = sev_color_map.get(sev, COLOR_LOW)
        badge_html  = render_severity_badge(sev)
        status_html = render_status_badge(row['status'])

        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-left:3px solid {left_border};border-radius:8px;
                    padding:0.85rem 1.25rem;margin-bottom:0.5rem;
                    display:flex;align-items:center;justify-content:space-between;">
            <div style="flex:1;">
                <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.3rem;">
                    {badge_html}
                    {status_html}
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;color:{COLOR_TEXT};">
                        {row['alert_type']}
                    </span>
                    <span style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};">
                        Score: <strong style="color:{COLOR_ACCENT};">{row['risk_score']}</strong>
                    </span>
                </div>
                <div style="font-size:0.8rem;color:{COLOR_TEXT_SEC};">
                    <code style="background:transparent;border:none;font-size:0.78rem;">{row['source_ip']}</code>
                    <span style="color:{COLOR_TEXT_MUTED};margin:0 0.4rem;">→</span>
                    <code style="background:transparent;border:none;font-size:0.78rem;">{row['destination_ip']}:{row.get('destination_port','?')}</code>
                    <span style="color:{COLOR_TEXT_MUTED};margin-left:0.75rem;">
                        {str(row.get('reason',''))[:80]}{'…' if len(str(row.get('reason',''))) > 80 else ''}
                    </span>
                </div>
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:{COLOR_TEXT_MUTED};
                        text-align:right;min-width:120px;">
                {str(row.get('last_seen',''))[:16]}
            </div>
        </div>
        """, unsafe_allow_html=True)

    if len(recent_alerts) > 8:
        st.caption(f"Showing 8 of {len(recent_alerts)} alerts — view all in **Alerts** →")
else:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:2rem;text-align:center;color:{COLOR_TEXT_MUTED};">
        <div style="font-size:1.2rem;margin-bottom:0.4rem;">🔔</div>
        <div>No alerts logged in the system</div>
        <div style="font-size:0.75rem;margin-top:0.25rem;">Run the detection pipeline or generate sample data from Settings</div>
    </div>
    """, unsafe_allow_html=True)


# ─── Auto-refresh trigger ──────────────────────────────────────────────────────
if _refresh_secs > 0:
    _time.sleep(_refresh_secs)
    st.rerun()
