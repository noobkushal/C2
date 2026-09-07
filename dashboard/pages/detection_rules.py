import streamlit as st
import pandas as pd
from src.database.repositories import get_detection_rules, update_detection_rule, get_alerts

st.title("⚙️ Behavioral Detection Rules Engine")
st.caption("Configure thresholds, toggle rule states, and inspect detection statistics")

rules = get_detection_rules()
alerts_df = get_alerts(limit=5000)

alert_counts = {}
last_triggered = {}

if not alerts_df.empty:
    for atype, group in alerts_df.groupby("alert_type"):
        alert_counts[atype] = len(group)
        last_triggered[atype] = group["last_seen"].max()

rule_type_map = {
    "RULE_BEACON": "BEACONING",
    "RULE_DNS_LONG": "DNS_ANOMALY",
    "RULE_DNS_FREQ": "DNS_ANOMALY",
    "RULE_DNS_SUBDOM": "DNS_ANOMALY",
    "RULE_RARE_DEST": "RARE_DESTINATION",
    "RULE_CONN_FREQ": "HIGH_FREQUENCY",
    "RULE_SUSP_PORT": "SUSPICIOUS_PORT"
}

st.subheader("Active Detection Rules Configuration")

for r in rules:
    with st.container():
        c1, c2, c3, c4 = st.columns([1, 4, 2, 2])
        
        atype = rule_type_map.get(r.rule_id, "OTHER")
        cnt = alert_counts.get(atype, 0)
        last_t = last_triggered.get(atype, "Never")
        
        with c1:
            enabled = st.toggle("Enabled", value=bool(r.enabled), key=f"toggle_{r.rule_id}")
            if enabled != bool(r.enabled):
                update_detection_rule(r.rule_id, enabled=int(enabled))
                st.toast(f"Updated {r.rule_id} enabled={enabled}")
                st.rerun()
                
        with c2:
            st.markdown(f"**{r.name}** (`{r.rule_id}`)")
            st.caption(f"{r.description} | Default Severity: **{r.severity}**")
            
        with c3:
            curr_thresh = r.threshold if r.threshold is not None else 0.0
            new_thresh = st.number_input(
                f"Threshold ({r.rule_id})",
                min_value=0.0, max_value=1000.0, value=float(curr_thresh), step=0.01,
                key=f"thresh_{r.rule_id}"
            )
            if new_thresh != curr_thresh:
                update_detection_rule(r.rule_id, threshold=new_thresh)
                st.toast(f"Updated {r.rule_id} threshold={new_thresh}")
                st.rerun()
                
        with c4:
            st.markdown(f"**Triggered Count**: `{cnt}`")
            st.caption(f"Last Fired: {last_t}")
            
        st.divider()
