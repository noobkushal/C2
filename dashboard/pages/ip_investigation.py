import streamlit as st
import plotly.express as px
import pandas as pd
from src.database.repositories import get_network_events, get_dns_events, get_alerts
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BORDER,
    render_page_header, render_severity_badge, render_status_badge, section_heading
)

render_page_header(
    "IP Investigation Workspace",
    "Comprehensive behavioral analysis for any IP address observed in your network",
    "🎯"
)

# ─── IP input ─────────────────────────────────────────────────────────────────
col_input, col_search = st.columns([4, 1])
with col_input:
    ip_query = st.text_input(
        "IP Address",
        placeholder="Enter IP address to investigate (e.g. 192.168.1.100)",
        label_visibility="collapsed"
    )
with col_search:
    search_btn = st.button("🔍  Investigate", type="primary", use_container_width=True)

# Allow session-state driven pre-population (e.g. from alert page)
if not ip_query and st.session_state.get("investigate_ip"):
    ip_query = st.session_state["investigate_ip"]

if not ip_query:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🎯</div>
        <div style="font-weight:500;margin-bottom:0.25rem;">Enter an IP address above to investigate</div>
        <div style="font-size:0.8rem;">
            Searches across all captured network events, DNS queries, and alerts for the specified IP.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Load data ────────────────────────────────────────────────────────────────
with st.spinner(f"Loading data for {ip_query}…"):
    src_events  = get_network_events(source_ip=ip_query,      limit=5000)
    dst_events  = get_network_events(destination_ip=ip_query, limit=5000)
    dns_events  = get_dns_events(source_ip=ip_query,          limit=1000)
    src_alerts  = get_alerts(source_ip=ip_query,              limit=200)
    dst_alerts  = get_alerts(destination_ip=ip_query,         limit=200)

# Combine all events
all_events = pd.concat([src_events, dst_events], ignore_index=True).drop_duplicates(subset=["event_id"]) if not src_events.empty or not dst_events.empty else pd.DataFrame()
all_alerts = pd.concat([src_alerts, dst_alerts], ignore_index=True).drop_duplicates(subset=["alert_id"]) if not src_alerts.empty or not dst_alerts.empty else pd.DataFrame()

if all_events.empty and dns_events.empty:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:2.5rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:1rem 0;">
        <div style="font-size:1.2rem;margin-bottom:0.3rem;">🔍</div>
        <div>No data found for <code>{ip_query}</code></div>
        <div style="font-size:0.78rem;margin-top:0.25rem;">
            This IP has no observed activity in the captured telemetry.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Summary header ───────────────────────────────────────────────────────────
first_seen = last_seen = "N/A"
if not all_events.empty and "timestamp" in all_events.columns:
    all_events["dt"] = pd.to_datetime(all_events["timestamp"], errors="coerce")
    all_events = all_events.dropna(subset=["dt"])
    first_seen = str(all_events["dt"].min())[:16]
    last_seen  = str(all_events["dt"].max())[:16]

alert_count = len(all_alerts)
risk_level  = "NONE"
if alert_count > 0 and "severity" in all_alerts.columns:
    if "CRITICAL" in all_alerts["severity"].values: risk_level = "CRITICAL"
    elif "HIGH"   in all_alerts["severity"].values: risk_level = "HIGH"
    elif "MEDIUM" in all_alerts["severity"].values: risk_level = "MEDIUM"
    else:                                            risk_level = "LOW"

risk_color_map = {
    "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW, "NONE": COLOR_SAFE
}
risk_color = risk_color_map.get(risk_level, COLOR_TEXT_MUTED)

st.markdown(f"""
<div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
            border-left:4px solid {risk_color};border-radius:10px;
            padding:1.25rem 1.5rem;margin-bottom:1.25rem;">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
        <div>
            <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
                <code style="font-size:1.1rem;font-weight:700;color:{COLOR_TEXT};
                             background:{COLOR_ELEVATED};padding:0.2em 0.6em;border-radius:5px;">
                    {ip_query}
                </code>
                {render_severity_badge(risk_level)}
            </div>
            <div style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};">
                First seen: <strong>{first_seen}</strong> &nbsp;·&nbsp;
                Last seen: <strong>{last_seen}</strong>
            </div>
        </div>
        <div style="text-align:right;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;
                        color:{risk_color};line-height:1;">{alert_count}</div>
            <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.1em;
                        color:{COLOR_TEXT_MUTED};font-weight:600;">Alerts</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ─── Activity KPIs ────────────────────────────────────────────────────────────
k1, k2, k3, k4, k5 = st.columns(5)
with k1: st.metric("Events (as Source)",      len(src_events))
with k2: st.metric("Events (as Dest)",        len(dst_events))
with k3: st.metric("DNS Queries",             len(dns_events))
with k4: st.metric("Related Alerts",          alert_count)
with k5:
    unique_ports = 0
    if not all_events.empty and "destination_port" in all_events.columns:
        unique_ports = all_events["destination_port"].dropna().nunique()
    st.metric("Unique Ports", unique_ports)

st.divider()

# ─── Charts ───────────────────────────────────────────────────────────────────
col_a, col_b = st.columns(2)

with col_a:
    section_heading("Connection Frequency Over Time")
    if not all_events.empty:
        ts_data = all_events.set_index("dt").resample("15min").size().reset_index(name="count")
        fig_ts  = px.area(
            ts_data, x="dt", y="count",
            color_discrete_sequence=[COLOR_ACCENT],
            labels={"dt": "Time", "count": "Connections"},
        )
        fig_ts.update_traces(fill="tozeroy", fillcolor="rgba(216,137,85,0.08)")
        fig_ts.update_layout(
            height=260, margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE, showlegend=False,
        )
        st.plotly_chart(fig_ts, use_container_width=True)
    else:
        st.info("No timeline data.")

with col_b:
    section_heading("Observed Ports (Destination)")
    if not all_events.empty and "destination_port" in all_events.columns:
        ports_data = (all_events["destination_port"].dropna().astype(int)
                      .value_counts().head(10).reset_index())
        ports_data.columns = ["port", "count"]
        fig_ports = px.bar(
            ports_data, x="port", y="count",
            color_discrete_sequence=[COLOR_LOW],
            labels={"port": "Port", "count": "Connections"},
        )
        fig_ports.update_layout(
            height=260, margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
        )
        st.plotly_chart(fig_ports, use_container_width=True)
    else:
        st.info("No port data.")

# ─── Tabbed details ───────────────────────────────────────────────────────────
st.divider()
t1, t2, t3, t4 = st.tabs([
    "🌐 Network Events",
    "🔍 DNS Queries",
    "🚨 Related Alerts",
    "📊 Top Destinations",
])

with t1:
    if not all_events.empty:
        show_cols = [c for c in ["timestamp", "source_ip", "destination_ip", "destination_port",
                                  "protocol", "bytes_sent", "log_source"] if c in all_events.columns]
        st.dataframe(all_events[show_cols].sort_values("timestamp", ascending=False),
                     use_container_width=True, hide_index=True, height=300)
    else:
        st.info("No network events found for this IP.")

with t2:
    if not dns_events.empty:
        st.dataframe(dns_events.sort_values("timestamp", ascending=False),
                     use_container_width=True, hide_index=True, height=300)
    else:
        st.info("No DNS queries found.")

with t3:
    if not all_alerts.empty:
        for _, row in all_alerts.iterrows():
            sev = row.get("severity", "LOW").upper()
            sev_colors = {
                "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
            }
            lb = sev_colors.get(sev, COLOR_LOW)
            st.markdown(f"""
            <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                        border-left:3px solid {lb};border-radius:7px;
                        padding:0.75rem 1.25rem;margin-bottom:0.4rem;">
                <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.25rem;">
                    {render_severity_badge(sev)}
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;">{row['alert_type']}</span>
                    <span style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};">Score: {row['risk_score']}</span>
                </div>
                <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};">{str(row.get('reason',''))[:120]}</div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No alerts associated with this IP.")

with t4:
    if not src_events.empty and "destination_ip" in src_events.columns:
        top_dst = (src_events["destination_ip"].value_counts().head(10).reset_index())
        top_dst.columns = ["destination_ip", "count"]
        fig_dst = px.bar(
            top_dst, x="count", y="destination_ip", orientation="h",
            color_discrete_sequence=[COLOR_SAFE],
        )
        fig_dst.update_layout(
            height=300, margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
            yaxis=dict(autorange="reversed"),
        )
        st.plotly_chart(fig_dst, use_container_width=True)
    else:
        st.info("No outbound connection data.")

# ─── Threat Intel note ────────────────────────────────────────────────────────
from src.services.threat_intel_service import enrich_ip, get_api_key

_has_any_key = bool(get_api_key("ABUSEIPDB_API_KEY") or get_api_key("VIRUSTOTAL_API_KEY"))

if not _has_any_key:
    st.markdown(f"""
    <div style="background:{COLOR_ELEVATED};border:1px solid {COLOR_BORDER_SUBTLE};
                border-radius:6px;padding:0.65rem 1rem;margin-top:1rem;font-size:0.78rem;
                color:{COLOR_TEXT_MUTED};">
        🔌 <strong>No external threat intelligence configured</strong> —
        Add an AbuseIPDB or VirusTotal API key in
        <strong>Settings → 🔌 Threat Intel</strong> to enrich IP reputation data.
    </div>
    """, unsafe_allow_html=True)
else:
    st.divider()
    section_heading("Threat Intelligence Enrichment")

    with st.spinner(f"Querying threat intelligence providers for {ip_query}…"):
        ti_results = enrich_ip(ip_query)

    if not ti_results:
        st.info("No threat intelligence results returned.")
    else:
        for res in ti_results:
            provider = res.get("provider", "Unknown")
            err      = res.get("error")

            if err:
                st.warning(f"⚠️ {provider}: {err}")
                continue

            if provider == "AbuseIPDB":
                score  = res.get("abuse_confidence_score", 0)
                sc_color = (
                    COLOR_CRITICAL if score >= 75 else
                    COLOR_HIGH     if score >= 50 else
                    COLOR_MEDIUM   if score >= 25 else
                    COLOR_SAFE
                )
                threat_label = (
                    "CRITICAL THREAT" if score >= 75 else
                    "HIGH RISK"       if score >= 50 else
                    "MODERATE"        if score >= 25 else
                    "CLEAN"
                )
                st.markdown(f"""
                <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                            border-left:4px solid {sc_color};border-radius:10px;
                            padding:1.1rem 1.5rem;margin-bottom:0.75rem;">
                    <div style="display:flex;align-items:center;justify-content:space-between;
                                flex-wrap:wrap;gap:1rem;">
                        <div>
                            <div style="font-weight:700;color:{COLOR_TEXT};margin-bottom:0.3rem;">
                                🛡️ AbuseIPDB
                            </div>
                            <div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;">
                                <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;
                                             color:{COLOR_TEXT_MUTED};">
                                    ISP: <strong style="color:{COLOR_TEXT};">{res.get('isp','?')}</strong>
                                </span>
                                <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;
                                             color:{COLOR_TEXT_MUTED};">
                                    Country: <strong style="color:{COLOR_TEXT};">{res.get('country_code','?')}</strong>
                                </span>
                                <span style="font-size:0.8rem;color:{COLOR_TEXT_MUTED};">
                                    Reports: <strong style="color:{COLOR_TEXT};">{res.get('total_reports', 0):,}</strong>
                                </span>
                                {('<span style="font-size:0.78rem;color:' + COLOR_SAFE + ';">✅ Whitelisted</span>')
                                 if res.get('is_whitelisted') else ''}
                            </div>
                        </div>
                        <div style="text-align:right;">
                            <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                                        font-weight:800;color:{sc_color};line-height:1;">{score}%</div>
                            <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.1em;
                                        font-weight:600;color:{sc_color};">{threat_label}</div>
                            <div style="font-size:0.68rem;color:{COLOR_TEXT_MUTED};margin-top:0.2rem;">
                                Abuse Confidence
                            </div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            elif provider == "VirusTotal":
                malicious   = res.get("malicious_votes", 0)
                suspicious  = res.get("suspicious_votes", 0)
                harmless    = res.get("harmless_votes", 0)
                undetected  = res.get("undetected_votes", 0)
                total_votes = malicious + suspicious + harmless + undetected
                vt_color = (
                    COLOR_CRITICAL if malicious >= 5 else
                    COLOR_HIGH     if malicious >= 2 else
                    COLOR_MEDIUM   if suspicious > 0 else
                    COLOR_SAFE
                )
                last_date = res.get("last_analysis_date", "")
                if last_date:
                    try:
                        import datetime as _dt
                        last_date = _dt.datetime.fromtimestamp(
                            int(last_date), tz=_dt.timezone.utc
                        ).strftime("%Y-%m-%d")
                    except Exception:
                        pass

                st.markdown(f"""
                <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                            border-left:4px solid {vt_color};border-radius:10px;
                            padding:1.1rem 1.5rem;margin-bottom:0.75rem;">
                    <div style="display:flex;align-items:center;justify-content:space-between;
                                flex-wrap:wrap;gap:1rem;">
                        <div>
                            <div style="font-weight:700;color:{COLOR_TEXT};margin-bottom:0.3rem;">
                                🦠 VirusTotal
                            </div>
                            <div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;">
                                <span style="font-size:0.8rem;color:{COLOR_CRITICAL};font-weight:600;">
                                    🔴 {malicious} malicious
                                </span>
                                <span style="font-size:0.8rem;color:{COLOR_MEDIUM};">
                                    🟡 {suspicious} suspicious
                                </span>
                                <span style="font-size:0.8rem;color:{COLOR_SAFE};">
                                    🟢 {harmless} harmless
                                </span>
                            </div>
                            <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-top:0.35rem;">
                                ASN: <strong style="color:{COLOR_TEXT};">{res.get('as_owner','?')}</strong>
                                &nbsp;·&nbsp;
                                Country: <strong style="color:{COLOR_TEXT};">{res.get('country','?')}</strong>
                                &nbsp;·&nbsp;
                                Last scan: <strong style="color:{COLOR_TEXT};">{last_date or 'N/A'}</strong>
                            </div>
                        </div>
                        <div style="text-align:right;">
                            <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                                        font-weight:800;color:{vt_color};line-height:1;">
                                {malicious}/{total_votes}
                            </div>
                            <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.1em;
                                        font-weight:600;color:{vt_color};">Detections</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
