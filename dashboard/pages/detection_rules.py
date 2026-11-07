import streamlit as st
import pandas as pd
from src.database.repositories import get_detection_rules, update_detection_rule, get_alerts
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BORDER,
    render_page_header, render_severity_badge, section_heading
)

render_page_header(
    "Behavioral Detection Rules Engine",
    "Configure thresholds, toggle rule states, and inspect detection statistics",
    "⚙️"
)

rules     = get_detection_rules()
alerts_df = get_alerts(limit=5000)

alert_counts   = {}
last_triggered = {}

if not alerts_df.empty:
    for atype, group in alerts_df.groupby("alert_type"):
        alert_counts[atype]   = len(group)
        last_triggered[atype] = group["last_seen"].max()

rule_type_map = {
    "RULE_BEACON":   "BEACONING",
    "RULE_DNS_LONG": "DNS_ANOMALY",
    "RULE_DNS_FREQ": "DNS_ANOMALY",
    "RULE_DNS_SUBDOM":"DNS_ANOMALY",
    "RULE_RARE_DEST":"RARE_DESTINATION",
    "RULE_CONN_FREQ":"HIGH_FREQUENCY",
    "RULE_SUSP_PORT":"SUSPICIOUS_PORT",
    "RULE_PORT_SCAN":"PORT_SCAN",
}

# ─── Summary stats ────────────────────────────────────────────────────────────
total_enabled  = sum(1 for r in rules if r.enabled)
total_disabled = len(rules) - total_enabled
total_fired    = sum(alert_counts.values())

k1, k2, k3, k4 = st.columns(4)
with k1: st.metric("Total Rules",     len(rules))
with k2: st.metric("Rules Enabled",   total_enabled)
with k3: st.metric("Rules Disabled",  total_disabled)
with k4: st.metric("Total Triggered", f"{total_fired:,}")

st.divider()
section_heading("Active Detection Rules Configuration")

for r in rules:
    atype   = rule_type_map.get(r.rule_id, "OTHER")
    cnt     = alert_counts.get(atype, 0)
    last_t  = last_triggered.get(atype, "Never")
    sev_badge = render_severity_badge(r.severity or "LOW")

    sev_color_map = {
        "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
        "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
    }
    left_border = sev_color_map.get((r.severity or "LOW").upper(), COLOR_LOW)

    enabled_indicator = COLOR_SAFE if r.enabled else COLOR_TEXT_MUTED

    with st.container():
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-left:3px solid {left_border};border-radius:8px;
                    padding:1rem 1.25rem;margin-bottom:0.5rem;">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
                <div style="flex:1;">
                    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.3rem;">
                        <span style="width:8px;height:8px;border-radius:50%;
                                     background:{enabled_indicator};display:inline-block;"></span>
                        <strong style="font-size:0.9rem;color:{COLOR_TEXT};">{r.name}</strong>
                        {sev_badge}
                        <code style="background:{COLOR_ELEVATED};padding:0.1em 0.45em;
                                     border-radius:3px;font-size:0.72rem;">{r.rule_id}</code>
                    </div>
                    <div style="font-size:0.8rem;color:{COLOR_TEXT_MUTED};">{r.description}</div>
                </div>
                <div style="text-align:right;min-width:180px;">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;
                                font-weight:600;color:{COLOR_ACCENT};">{cnt:,}</div>
                    <div style="font-size:0.68rem;color:{COLOR_TEXT_MUTED};text-transform:uppercase;">
                        Alerts Fired
                    </div>
                    <div style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};margin-top:0.2rem;">
                        Last: {str(last_t)[:16] if last_t != "Never" else "Never"}
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        ctrl1, ctrl2, ctrl3 = st.columns([1, 2, 1])

        with ctrl1:
            enabled = st.toggle("Enabled", value=bool(r.enabled), key=f"toggle_{r.rule_id}")
            if enabled != bool(r.enabled):
                update_detection_rule(r.rule_id, enabled=int(enabled))
                status_text = "enabled" if enabled else "disabled"
                st.toast(f"{r.rule_id} {status_text}", icon="⚙️")
                st.rerun()

        with ctrl2:
            curr_thresh = r.threshold if r.threshold is not None else 0.0
            new_thresh  = st.number_input(
                f"Threshold",
                min_value=0.0, max_value=10000.0,
                value=float(curr_thresh), step=0.01,
                key=f"thresh_{r.rule_id}",
                label_visibility="visible",
                help=f"Alert trigger threshold for rule {r.rule_id}"
            )
            if abs(new_thresh - curr_thresh) > 1e-6:
                update_detection_rule(r.rule_id, threshold=new_thresh)
                st.toast(f"{r.rule_id} threshold → {new_thresh}", icon="🔧")
                st.rerun()

        with ctrl3:
            st.markdown(f"""
            <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};padding:0.4rem 0;">
                Alert type: <code style="font-size:0.72rem;">{atype}</code>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<div style='height:0.25rem;'></div>", unsafe_allow_html=True)
