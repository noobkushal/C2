import json
import os
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
from src.database.repositories import (
    get_overview_kpis,
    get_alerts,
    get_network_events,
    get_dns_events
)
from src.detection.beacon_detection import detect_beaconing
from src.detection.dns_detection import detect_dns_anomalies

st.title("📄 Executive & Forensic Report Generator")
st.caption("Generate, view, and export structured SOC intelligence reports in JSON and CSV")

os.makedirs("data/alerts", exist_ok=True)

r_type = st.selectbox(
    "Select Report Type to Generate",
    options=[
        "Daily Network Summary",
        "Alert Summary",
        "C2 Beaconing Detection Report",
        "DNS Anomaly Report",
        "Investigation Summary Report"
    ]
)

if st.button(f"Generate '{r_type}' 🚀"):
    now_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_data = {}
    csv_df = pd.DataFrame()
    filename_base = r_type.lower().replace(" ", "_") + f"_{now_str}"

    if r_type == "Daily Network Summary":
        kpis = get_overview_kpis()
        report_data = {"report_type": r_type, "generated_at": now_str, "kpis": kpis}
        csv_df = pd.DataFrame([kpis])

    elif r_type == "Alert Summary":
        alerts_df = get_alerts(limit=5000)
        report_data = {
            "report_type": r_type,
            "generated_at": now_str,
            "total_alerts": len(alerts_df),
            "alerts": alerts_df.to_dict(orient="records") if not alerts_df.empty else []
        }
        csv_df = alerts_df

    elif r_type == "C2 Beaconing Detection Report":
        events_df = get_network_events(limit=10000)
        candidates = detect_beaconing(events_df) if not events_df.empty else []
        report_data = {
            "report_type": r_type,
            "generated_at": now_str,
            "candidate_count": len(candidates),
            "candidates": candidates
        }
        csv_df = pd.DataFrame(candidates)

    elif r_type == "DNS Anomaly Report":
        dns_df = get_dns_events(limit=10000)
        anomalies = detect_dns_anomalies(dns_df) if not dns_df.empty else []
        report_data = {
            "report_type": r_type,
            "generated_at": now_str,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies
        }
        csv_df = pd.DataFrame(anomalies)

    elif r_type == "Investigation Summary Report":
        alerts_df = get_alerts(status="INVESTIGATING", limit=1000)
        report_data = {
            "report_type": r_type,
            "generated_at": now_str,
            "investigating_count": len(alerts_df),
            "records": alerts_df.to_dict(orient="records") if not alerts_df.empty else []
        }
        csv_df = alerts_df

    # Save to data/alerts/
    json_path = os.path.join("data/alerts", f"{filename_base}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    st.success(f"Report saved to evidence locker: `{json_path}`")

    # Render Preview
    st.subheader("Report Preview")
    st.json(report_data)

    # Download Buttons
    json_bytes = json.dumps(report_data, indent=2).encode("utf-8")
    c_d1, c_d2 = st.columns(2)
    with c_d1:
        st.download_button(
            "Download JSON Report 📥",
            data=json_bytes,
            file_name=f"{filename_base}.json",
            mime="application/json"
        )
    with c_d2:
        if not csv_df.empty:
            csv_bytes = csv_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download CSV Export 📊",
                data=csv_bytes,
                file_name=f"{filename_base}.csv",
                mime="text/csv"
            )
