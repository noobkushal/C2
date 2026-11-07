import json
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from src.database.repositories import get_alerts, get_network_events, get_dns_events, upsert_investigation
from src.services.alert_service import get_alert_details, update_status
from src.services.mitre_mapping import get_mitre_context
from dashboard.theme import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_ACCENT,
    COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED, COLOR_BORDER,
    render_page_header, render_severity_badge, render_status_badge, section_heading
)

render_page_header(
    "Threat Investigation Desk",
    "Deep-dive forensic analysis, signal breakdown, timeline, and analyst notes",
    "🔬"
)

all_alerts = get_alerts(limit=500)

if all_alerts.empty:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🔔</div>
        <div style="font-weight:500;margin-bottom:0.25rem;">No alerts to investigate</div>
        <div style="font-size:0.8rem;">Run the detection pipeline or generate sample data from Settings.</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Alert selector ───────────────────────────────────────────────────────────
alert_options = {
    f"{r['alert_type']} | {r['source_ip']} → {r['destination_ip']}:{r['destination_port']} [{r['severity']}] ({r['alert_id'][:8]}…)": r['alert_id']
    for _, r in all_alerts.iterrows()
}

selected_id  = st.session_state.get("selected_alert_id")
default_idx  = 0
if selected_id:
    for idx2, (label, aid) in enumerate(alert_options.items()):
        if aid == selected_id:
            default_idx = idx2
            break

selected_label = st.selectbox(
    "Select Alert to Investigate",
    list(alert_options.keys()),
    index=default_idx
)
alert_id = alert_options[selected_label]
st.session_state["selected_alert_id"] = alert_id

alert, inv = get_alert_details(alert_id)
if not alert:
    st.error(f"Alert ID `{alert_id}` not found.")
    st.stop()

# ─── Alert summary card ───────────────────────────────────────────────────────
sev = alert.severity.upper()
sev_color_map = {
    "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
}
left_border = sev_color_map.get(sev, COLOR_LOW)

st.markdown(f"""
<div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
            border-left:4px solid {left_border};border-radius:10px;
            padding:1.25rem 1.5rem;margin-bottom:1.25rem;">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
        <div>
            <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.6rem;">
                {render_severity_badge(sev)}
                {render_status_badge(alert.status)}
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.88rem;
                             color:{COLOR_TEXT};font-weight:600;">{alert.alert_type}</span>
            </div>
            <div style="font-size:0.85rem;color:{COLOR_TEXT_SEC};margin-bottom:0.4rem;">
                <code style="background:{COLOR_ELEVATED};padding:0.15em 0.5em;border-radius:4px;">{alert.source_ip}</code>
                <span style="color:{COLOR_TEXT_MUTED};margin:0 0.6rem;">→</span>
                <code style="background:{COLOR_ELEVATED};padding:0.15em 0.5em;border-radius:4px;">{alert.destination_ip}:{alert.destination_port}</code>
            </div>
            <div style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};">
                {alert.reason}
            </div>
        </div>
        <div style="text-align:right;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;
                        color:{COLOR_ACCENT};line-height:1;">{alert.risk_score}</div>
            <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.1em;
                        color:{COLOR_TEXT_MUTED};font-weight:600;">Risk Score</div>
            <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};margin-top:0.3rem;">
                Confidence: {alert.confidence:.2f}
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Time metadata
tm1, tm2, tm3 = st.columns(3)
with tm1:
    st.markdown(f"<div class='ns-data-row'><span class='ns-data-label'>Alert ID</span><span class='ns-data-value'>{alert.alert_id[:16]}…</span></div>", unsafe_allow_html=True)
with tm2:
    st.markdown(f"<div class='ns-data-row'><span class='ns-data-label'>First Seen</span><span class='ns-data-value'>{str(alert.first_seen)[:16]}</span></div>", unsafe_allow_html=True)
with tm3:
    st.markdown(f"<div class='ns-data-row'><span class='ns-data-label'>Last Seen</span><span class='ns-data-value'>{str(alert.last_seen)[:16]}</span></div>", unsafe_allow_html=True)

# ─── Main content columns ─────────────────────────────────────────────────────
col_main, col_side = st.columns([3, 1])

with col_main:
    # Risk score breakdown
    evidence = {}
    try:
        evidence = json.loads(alert.evidence) if alert.evidence else {}
    except Exception:
        evidence = {}

    signals = evidence.get("signals", [])
    if signals:
        section_heading("Risk Score Breakdown")
        sig_df   = pd.DataFrame(signals)
        pts_col  = "points" if "points" in sig_df.columns else ("contributes_points" if "contributes_points" in sig_df.columns else None)
        name_col = "name"   if "name"   in sig_df.columns else ("indicator_name"     if "indicator_name"     in sig_df.columns else None)

        if pts_col and name_col:
            sig_df[pts_col] = sig_df[pts_col].astype(int)
            fig_sig = px.bar(
                sig_df, x=pts_col, y=name_col, orientation="h",
                labels={pts_col: "Risk Points", name_col: "Signal"},
                color_discrete_sequence=[COLOR_HIGH],
            )
            fig_sig.update_layout(
                height=200,
                margin=dict(l=10, r=10, t=10, b=20),
                paper_bgcolor=COLOR_SURFACE,
                plot_bgcolor=COLOR_SURFACE,
            )
            st.plotly_chart(fig_sig, use_container_width=True)

    # Beacon stats if BEACONING
    if alert.alert_type == "BEACONING":
        section_heading("Beacon Interval Statistics")
        net_events = get_network_events(
            source_ip=alert.source_ip,
            destination_ip=alert.destination_ip,
            limit=1000
        )
        if not net_events.empty:
            from src.detection.beacon_detection import calculate_group_beacon_stats
            bstats = calculate_group_beacon_stats(net_events["timestamp"].tolist())
            bc1, bc2, bc3, bc4, bc5 = st.columns(5)
            with bc1: st.metric("Connections",    bstats["connection_count"])
            with bc2: st.metric("Mean Interval",  f"{bstats['mean']:.2f}s")
            with bc3: st.metric("Median Interval",f"{bstats['median']:.2f}s")
            with bc4: st.metric("Std Dev",         f"{bstats['stdev']:.2f}s")
            with bc5: st.metric("CV",              f"{bstats['cv']:.4f}" if bstats['cv'] is not None else "N/A")

            # Beacon timeline
            net_events["dt"] = pd.to_datetime(net_events["timestamp"], errors="coerce")
            net_events = net_events.dropna(subset=["dt"]).sort_values("dt")
            fig_beacon = go.Figure()
            fig_beacon.add_trace(go.Scatter(
                x=net_events["dt"],
                y=[1] * len(net_events),
                mode="markers",
                marker=dict(
                    size=14, symbol="line-ns",
                    color=COLOR_HIGH,
                    line=dict(width=3, color=COLOR_CRITICAL)
                ),
                hovertemplate="<b>%{x}</b><extra></extra>"
            ))
            fig_beacon.update_layout(
                height=200,
                margin=dict(l=10, r=10, t=10, b=20),
                paper_bgcolor=COLOR_SURFACE,
                plot_bgcolor=COLOR_SURFACE,
                yaxis=dict(showticklabels=False, range=[0.5, 1.5]),
                xaxis_title="Timestamp (UTC)"
            )
            st.plotly_chart(fig_beacon, use_container_width=True)

    # Activity timeline
    section_heading("Suspicious Activity Timeline")
    related_events = get_network_events(source_ip=alert.source_ip, limit=500)
    if not related_events.empty:
        related_events["dt"] = pd.to_datetime(related_events["timestamp"], errors="coerce")
        related_events = related_events.dropna(subset=["dt"])
        fig_time = px.scatter(
            related_events, x="dt", y="protocol", color="log_source",
            hover_data=["source_ip", "destination_ip", "destination_port", "domain"],
            color_discrete_sequence=[COLOR_LOW, COLOR_SAFE, COLOR_HIGH, COLOR_ACCENT],
        )
        fig_time.update_layout(
            height=220,
            margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE,
            plot_bgcolor=COLOR_SURFACE,
        )
        st.plotly_chart(fig_time, use_container_width=True)
    else:
        st.info("No related timeline events found.")

    # Evidence tabs
    t1, t2, t3, t4 = st.tabs([
        "Network Events", "DNS Queries", "Raw Evidence", "PCAP Reference"
    ])

    with t1:
        flows = get_network_events(
            source_ip=alert.source_ip, destination_ip=alert.destination_ip, limit=100
        )
        if not flows.empty:
            st.dataframe(flows, use_container_width=True, hide_index=True, height=280)
        else:
            st.info("No explicit network flows matched.")

    with t2:
        dns = get_dns_events(source_ip=alert.source_ip, limit=100)
        if not dns.empty:
            st.dataframe(dns, use_container_width=True, hide_index=True, height=280)
        else:
            st.info("No DNS events recorded for this source IP.")

    with t3:
        if evidence:
            st.json(evidence)
        else:
            st.info("No evidence JSON attached to this alert.")

    with t4:
        pcap_ref = "N/A"
        if not related_events.empty and "pcap_reference" in related_events.columns:
            non_null = related_events["pcap_reference"].dropna()
            if not non_null.empty:
                pcap_ref = non_null.iloc[0]
        st.code(f"Source PCAP: {pcap_ref}", language="bash")
        st.caption("PCAPs stored read-only under data/raw/. Upload PCAPs via PCAP Analysis page.")

with col_side:
    # MITRE ATT&CK context
    section_heading("MITRE ATT&CK")
    mitre_techs = get_mitre_context(alert.alert_type)
    for t in mitre_techs:
        st.markdown(f"""
        <div style="background:{COLOR_ELEVATED};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-radius:6px;padding:0.75rem;margin-bottom:0.5rem;">
            <div>
                <span class="ns-mitre-tag">{t['technique_id']}</span>
            </div>
            <div style="font-size:0.82rem;font-weight:600;color:{COLOR_TEXT};margin:0.35rem 0 0.2rem 0;">
                {t['name']}
            </div>
            <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};">{t['note']}</div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # Quick status change
    section_heading("Quick Actions")
    new_status = st.selectbox(
        "Alert Status",
        options=["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"],
        index=["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"].index(alert.status)
        if alert.status in ["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"] else 0
    )
    if st.button("Update Status", use_container_width=True, type="primary"):
        update_status(alert_id=alert.alert_id, new_status=new_status)
        st.toast("Status updated", icon="✅")
        st.rerun()

# ─── Analyst notes ────────────────────────────────────────────────────────────
st.divider()
section_heading("Analyst Triage & Investigation Notes")

inv_col1, inv_col2 = st.columns([3, 1])

with inv_col1:
    curr_notes = inv.notes if inv else ""
    if curr_notes:
        st.markdown(f"""
        <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};margin-bottom:0.5rem;">
            AUDIT TRAIL
        </div>
        """, unsafe_allow_html=True)
        # Parse and display note lines
        note_lines = [l for l in curr_notes.split("\n") if l.strip()]
        for line in note_lines[-10:]:  # Show last 10 notes
            if line.startswith("["):
                parts = line.split("]", 1)
                timestamp = parts[0][1:] if len(parts) > 1 else ""
                content   = parts[1].strip() if len(parts) > 1 else line
            else:
                timestamp, content = "", line
            st.markdown(f"""
            <div class="ns-note-card">
                <div class="ns-note-meta">{timestamp}</div>
                <div>{content}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No investigation notes yet.")

with inv_col2:
    curr_verdict = inv.verdict if inv else "UNKNOWN"

with st.form("investigation_form"):
    f1_col, f2_col = st.columns(2)
    with f1_col:
        new_verdict = st.selectbox(
            "Verdict",
            options=["UNKNOWN", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"],
            index=["UNKNOWN", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"].index(curr_verdict)
            if curr_verdict in ["UNKNOWN", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"] else 0
        )
    with f2_col:
        new_analyst_status = st.selectbox(
            "Investigation Status",
            options=["INVESTIGATING", "ESCALATED", "RESOLVED", "CLOSED"],
        )
    add_note = st.text_area(
        "Add Note / Analyst Observation",
        placeholder="Analyst observation, context, or action taken…",
        height=90
    )
    if st.form_submit_button("💾  Save Investigation Update", type="primary"):
        update_status(
            alert_id=alert.alert_id,
            new_status=new_status,
            analyst_note=add_note.strip() if add_note.strip() else f"Status → {new_status}",
            verdict=new_verdict
        )
        st.success("Investigation record saved.")
        st.rerun()
