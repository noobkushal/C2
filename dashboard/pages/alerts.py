import streamlit as st
import pandas as pd
from src.database.repositories import get_alerts

st.title("🚨 Alert Management & Triage")
st.caption("Active detection alerts requiring SOC analyst investigation")

tabs = st.tabs(["All", "New", "Investigating", "Confirmed", "False Positive", "Closed"])

tab_status_map = {
    "All": "ALL",
    "New": "NEW",
    "Investigating": "INVESTIGATING",
    "Confirmed": "CONFIRMED",
    "False Positive": "FALSE_POSITIVE",
    "Closed": "CLOSED"
}

# Filters
c1, c2, c3 = st.columns(3)
with c1:
    severity_filter = st.selectbox("Severity", options=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
with c2:
    alert_type_filter = st.selectbox("Alert Type", options=["ALL", "BEACONING", "DNS_ANOMALY", "RARE_DESTINATION", "HIGH_FREQUENCY", "SUSPICIOUS_PORT"])
with c3:
    src_search = st.text_input("Filter Source/Destination IP", value="")

def render_alert_tab(status_val: str):
    sev = severity_filter if severity_filter != "ALL" else None
    atype = alert_type_filter if alert_type_filter != "ALL" else None

    alerts_df = get_alerts(
        status=status_val,
        severity=sev,
        alert_type=atype,
        source_ip=src_search or None,
        limit=200
    )

    if alerts_df.empty:
        st.info("No alerts matching selected tab and filters.")
        return

    st.write(f"Showing {len(alerts_df)} alert records:")
    
    # Table header
    for idx, row in alerts_df.iterrows():
        with st.container():
            col_sev, col_info, col_btn = st.columns([1, 4, 1])
            with col_sev:
                sev_color = "red" if row['severity'] == "CRITICAL" else "orange" if row['severity'] == "HIGH" else "yellow" if row['severity'] == "MEDIUM" else "blue"
                st.markdown(f"**:{sev_color}[{row['severity']}]**\n\nScore: **{row['risk_score']}**")
            with col_info:
                st.markdown(f"**{row['alert_type']}** | `{row['source_ip']}` ➔ `{row['destination_ip']}:{row['destination_port']}`")
                st.caption(f"Reason: {row['reason']} | Last Seen: {row['last_seen']} | Status: `{row['status']}`")
            with col_btn:
                if st.button("Inspect 🔍", key=f"btn_{row['alert_id']}"):
                    st.session_state["selected_alert_id"] = row["alert_id"]
                    st.session_state["current_page"] = "Investigation"
                    st.rerun()
            st.divider()

for tab, (tab_name, status_val) in zip(tabs, tab_status_map.items()):
    with tab:
        render_alert_tab(status_val)
