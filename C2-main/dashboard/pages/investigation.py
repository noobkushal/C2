import json
import streamlit as st
import plotly.express as px
import pandas as pd
from src.database.repositories import get_alerts, get_network_events, get_dns_events
from src.services.alert_service import get_alert_details, update_status
from src.services.mitre_mapping import get_mitre_context
from dashboard.theme import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE,
    COLOR_SURFACE, COLOR_BORDER_SUBTLE
)

st.title("🔬 Threat Investigation Desk")
st.caption("Deep-dive forensic analysis, signal breakdown, timeline, and analyst notes")

all_alerts = get_alerts(limit=500)

if all_alerts.empty:
    st.info("No alerts found in system to investigate. Run the detection pipeline or generate sample data.")
    st.stop()

# Build alert dropdown options
alert_options = {
    f"{r['alert_type']} | {r['source_ip']} -> {r['destination_ip']}:{r['destination_port']} [{r['severity']}] ({r['alert_id'][:8]}...)": r['alert_id']
    for _, r in all_alerts.iterrows()
}

selected_id = st.session_state.get("selected_alert_id")
default_idx = 0
if selected_id:
    for idx, (label, aid) in enumerate(alert_options.items()):
        if aid == selected_id:
            default_idx = idx
            break

selected_label = st.selectbox("Select Alert to Investigate", list(alert_options.keys()), index=default_idx)
alert_id = alert_options[selected_label]
st.session_state["selected_alert_id"] = alert_id

alert, inv = get_alert_details(alert_id)
if not alert:
    st.error(f"Alert ID {alert_id} not found.")
    st.stop()

# 1. Alert Summary Card
st.subheader("📌 Alert Overview")
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"**Alert ID**: `{alert.alert_id}`")
    st.markdown(f"**Type**: `{alert.alert_type}`")
with c2:
    sev_color = "red" if alert.severity == "CRITICAL" else "orange" if alert.severity == "HIGH" else "yellow" if alert.severity == "MEDIUM" else "blue"
    st.markdown(f"**Severity**: **:{sev_color}[{alert.severity}]**")
    st.markdown(f"**Risk Score**: `{alert.risk_score} / 100`")
with c3:
    st.markdown(f"**Confidence**: `{alert.confidence:.2f}`")
    st.markdown(f"**Source**: `{alert.source_ip}`")
with c4:
    st.markdown(f"**Destination**: `{alert.destination_ip}:{alert.destination_port}`")
    st.markdown(f"**Current Status**: `{alert.status}`")

st.info(f"**Summary Reason**: {alert.reason}")

# Parse evidence JSON
evidence = {}
try:
    evidence = json.loads(alert.evidence) if alert.evidence else {}
except Exception:
    evidence = {}

# 2. Risk Score Breakdown Chart
st.subheader("🎯 Risk Score Breakdown")
signals = evidence.get("signals", [])
if signals:
    sig_df = pd.DataFrame(signals)
    pts_col = "points" if "points" in sig_df.columns else "contributes_points"
    sig_df[pts_col] = sig_df[pts_col].astype(int)
    name_col = "name" if "name" in sig_df.columns else "indicator_name"
    
    fig_sig = px.bar(
        sig_df, x=pts_col, y=name_col, orientation="h",
        labels={pts_col: "Risk Points", name_col: "Detection Signal"},
        color_discrete_sequence=[COLOR_HIGH],
        title="Contributing Risk Signals"
    )
    fig_sig.update_layout(height=220, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig_sig, use_container_width=True)

# 3. Beacon Statistics (If BEACONING)
if alert.alert_type == "BEACONING":
    st.subheader("📡 Beacon Interval Statistics")
    net_events = get_network_events(source_ip=alert.source_ip, destination_ip=alert.destination_ip, limit=1000)
    if not net_events.empty:
        from src.detection.beacon_detection import calculate_group_beacon_stats
        bstats = calculate_group_beacon_stats(net_events["timestamp"].tolist())
        
        bc1, bc2, bc3, bc4, bc5 = st.columns(5)
        with bc1: st.metric("Connections", bstats["connection_count"])
        with bc2: st.metric("Mean Interval", f"{bstats['mean']:.2f}s")
        with bc3: st.metric("Median Interval", f"{bstats['median']:.2f}s")
        with bc4: st.metric("Stdev (Deviation)", f"{bstats['stdev']:.2f}s")
        with bc5: st.metric("CV", f"{bstats['cv']:.4f}" if bstats['cv'] is not None else "N/A")

# 4. Activity Timeline
st.subheader("📈 Suspicious Activity Timeline")
related_events = get_network_events(source_ip=alert.source_ip, limit=500)
if not related_events.empty:
    related_events["dt"] = pd.to_datetime(related_events["timestamp"])
    fig_time = px.scatter(
        related_events, x="dt", y="protocol", color="log_source",
        hover_data=["source_ip", "destination_ip", "destination_port", "domain"],
        title="Event Flow Sequence Timeline",
        color_discrete_sequence=[COLOR_LOW, COLOR_SAFE, COLOR_HIGH]
    )
    fig_time.update_layout(height=250, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig_time, use_container_width=True)

# 5. Related Telemetry Tables
t1, t2, t3 = st.tabs(["Related Network Events", "Related DNS Queries", "PCAP Reference"])

with t1:
    st.write(f"Network flow events for `{alert.source_ip}` ➔ `{alert.destination_ip}`:")
    flows = get_network_events(source_ip=alert.source_ip, destination_ip=alert.destination_ip, limit=100)
    if not flows.empty:
        st.dataframe(flows, use_container_width=True, hide_index=True)
    else:
        st.info("No explicit network flows matched.")

with t2:
    st.write(f"DNS queries originating from source `{alert.source_ip}`:")
    dns = get_dns_events(source_ip=alert.source_ip, limit=100)
    if not dns.empty:
        st.dataframe(dns, use_container_width=True, hide_index=True)
    else:
        st.info("No DNS events recorded for this source IP.")

with t3:
    st.subheader("PCAP File Reference")
    pcap_ref = related_events["pcap_reference"].dropna().iloc[0] if not related_events.empty and "pcap_reference" in related_events.columns and not related_events["pcap_reference"].dropna().empty else "N/A (Synthetic or Direct Telemetry)"
    st.code(f"Source PCAP Path: {pcap_ref}", language="bash")
    st.caption("PCAPs are stored read-only under data/raw/.")

# 6. Static MITRE ATT&CK Context
st.divider()
st.subheader("🛡️ Relevant ATT&CK Context")
mitre_techs = get_mitre_context(alert.alert_type)
for t in mitre_techs:
    st.markdown(f"- **{t['technique_id']} — {t['name']}**")
    st.caption(f"  _{t['note']}_")

# 7. Analyst Action & Notes Form
st.divider()
st.subheader("📝 Analyst Triage & Notes")

with st.form("investigation_form"):
    curr_status = alert.status
    curr_verdict = inv.verdict if inv else "UNKNOWN"
    curr_notes = inv.notes if inv else ""
    
    st.markdown(f"**Existing Audit Trail Notes**:")
    st.text_area("Notes History", value=curr_notes, height=120, disabled=True)
    
    f1, f2 = st.columns(2)
    with f1:
        new_status = st.selectbox("Update Alert Status", options=["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"], index=["NEW", "INVESTIGATING", "CONFIRMED", "FALSE_POSITIVE", "CLOSED"].index(curr_status))
    with f2:
        new_verdict = st.selectbox("Assign Investigation Verdict", options=["UNKNOWN", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"], index=["UNKNOWN", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"].index(curr_verdict if curr_verdict in ["UNKNOWN", "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN"] else "UNKNOWN"))
        
    add_note = st.text_input("Add Analyst Note / Transition Reason", value="")
    
    submit = st.form_submit_button("Save Investigation Update 💾")
    if submit:
        update_status(
            alert_id=alert.alert_id,
            new_status=new_status,
            analyst_note=add_note if add_note else f"Status changed to {new_status}",
            verdict=new_verdict
        )
        st.success("Investigation record updated successfully!")
        st.rerun()
