import json
import os
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
from src.database.repositories import (
    get_overview_kpis, get_alerts, get_network_events, get_dns_events
)
from src.detection.beacon_detection import detect_beaconing
from src.detection.dns_detection import detect_dns_anomalies
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, render_page_header, section_heading
)

render_page_header(
    "Executive & Forensic Report Generator",
    "Generate, preview, and export structured SOC intelligence reports in JSON and CSV",
    "📄"
)

os.makedirs("data/alerts", exist_ok=True)

# ─── Report type selector ─────────────────────────────────────────────────────
section_heading("Report Configuration")

col_type, col_gen = st.columns([3, 1])
with col_type:
    r_type = st.selectbox(
        "Report Type",
        options=[
            "Daily Network Summary",
            "Alert Summary",
            "C2 Beaconing Detection Report",
            "DNS Anomaly Report",
            "Investigation Summary Report",
        ],
    )

# ─── Recent reports list ──────────────────────────────────────────────────────
report_files = []
try:
    report_files = sorted(
        [f for f in os.listdir("data/alerts") if f.endswith(".json")],
        reverse=True
    )[:5]
except Exception:
    pass

if report_files:
    with st.expander("📂  Recent Reports (last 5)", expanded=False):
        for fname in report_files:
            fpath = os.path.join("data/alerts", fname)
            fsize = os.path.getsize(fpath)
            st.markdown(f"""
            <div style="display:flex;justify-content:space-between;align-items:center;
                        padding:0.4rem 0;border-bottom:1px solid {COLOR_BORDER_SUBTLE};
                        font-size:0.82rem;">
                <span style="font-family:'JetBrains Mono',monospace;">{fname}</span>
                <span style="color:{COLOR_TEXT_MUTED};">{fsize//1024:.0f} KB</span>
            </div>
            """, unsafe_allow_html=True)

st.divider()

# ─── Generate button ──────────────────────────────────────────────────────────
if st.button(f"🚀  Generate Report — '{r_type}'", type="primary", use_container_width=False):
    now_str     = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_data = {}
    csv_df      = pd.DataFrame()
    filename_base = r_type.lower().replace(" ", "_") + f"_{now_str}"

    with st.spinner(f"Generating '{r_type}'…"):
        if r_type == "Daily Network Summary":
            kpis = get_overview_kpis()
            report_data = {"report_type": r_type, "generated_at": now_str, "kpis": kpis}
            csv_df = pd.DataFrame([kpis])

        elif r_type == "Alert Summary":
            alerts_df = get_alerts(limit=5000)
            report_data = {
                "report_type":   r_type,
                "generated_at":  now_str,
                "total_alerts":  len(alerts_df),
                "by_severity":   alerts_df["severity"].value_counts().to_dict() if not alerts_df.empty else {},
                "by_status":     alerts_df["status"].value_counts().to_dict() if not alerts_df.empty else {},
                "alerts":        alerts_df.to_dict(orient="records") if not alerts_df.empty else []
            }
            csv_df = alerts_df

        elif r_type == "C2 Beaconing Detection Report":
            events_df  = get_network_events(limit=10000)
            candidates = detect_beaconing(events_df) if not events_df.empty else []
            report_data = {
                "report_type":     r_type,
                "generated_at":    now_str,
                "events_analyzed": len(events_df),
                "candidate_count": len(candidates),
                "candidates":      candidates
            }
            csv_df = pd.DataFrame(candidates)

        elif r_type == "DNS Anomaly Report":
            dns_df    = get_dns_events(limit=10000)
            anomalies = detect_dns_anomalies(dns_df) if not dns_df.empty else []
            report_data = {
                "report_type":   r_type,
                "generated_at":  now_str,
                "queries_analyzed": len(dns_df),
                "anomaly_count": len(anomalies),
                "anomalies":     anomalies
            }
            csv_df = pd.DataFrame(anomalies)

        elif r_type == "Investigation Summary Report":
            alerts_df = get_alerts(status="INVESTIGATING", limit=1000)
            report_data = {
                "report_type":        r_type,
                "generated_at":       now_str,
                "investigating_count":len(alerts_df),
                "records":            alerts_df.to_dict(orient="records") if not alerts_df.empty else []
            }
            csv_df = alerts_df

    # Save JSON
    json_path = os.path.join("data/alerts", f"{filename_base}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    st.success(f"✅ Report saved: `{json_path}`")

    # ─── Download buttons ─────────────────────────────────────────────────────
    st.markdown(f"<div class='ns-section-heading'>Download Report</div>", unsafe_allow_html=True)
    d1, d2, d3 = st.columns(3)
    json_bytes = json.dumps(report_data, indent=2).encode("utf-8")

    with d1:
        st.download_button(
            "📥  JSON Report",
            data=json_bytes,
            file_name=f"{filename_base}.json",
            mime="application/json",
            use_container_width=True,
            type="primary"
        )
    with d2:
        if not csv_df.empty:
            csv_bytes = csv_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📊  CSV Export",
                data=csv_bytes,
                file_name=f"{filename_base}.csv",
                mime="text/csv",
                use_container_width=True,
            )
    with d3:
        # Summary stats display
        record_count = (
            report_data.get("total_alerts") or
            report_data.get("candidate_count") or
            report_data.get("anomaly_count") or
            report_data.get("investigating_count") or
            len(csv_df)
        )
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-radius:8px;padding:0.85rem;text-align:center;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                        font-weight:600;color:{COLOR_ACCENT};">{record_count}</div>
            <div style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};text-transform:uppercase;">Records</div>
        </div>
        """, unsafe_allow_html=True)

    # ─── Preview ──────────────────────────────────────────────────────────────
    with st.expander("🔍  Report Preview (JSON)", expanded=True):
        st.json(report_data)
