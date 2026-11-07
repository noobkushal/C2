import streamlit as st
import plotly.express as px
import pandas as pd
from src.database.repositories import get_dns_events
from src.detection.dns_detection import detect_dns_anomalies
from dashboard.theme import (
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE, COLOR_ACCENT,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_TEXT, COLOR_TEXT_MUTED,
    render_page_header, section_heading
)

render_page_header(
    "DNS Anomaly & Tunneling Analysis",
    "Deep inspection of domain query patterns, DGA indicators, and subdomain volume",
    "🔍"
)

st.markdown(f"""
<div style="background:rgba(92,143,190,0.07);border:1px solid rgba(92,143,190,0.25);
            border-radius:7px;padding:0.65rem 1rem;margin-bottom:1rem;font-size:0.82rem;">
    ℹ️ <strong>Analysis Disclaimer:</strong> These indicators contribute to investigation risk.
    They do not, individually or combined, constitute proof of malicious activity.
</div>
""", unsafe_allow_html=True)

dns_df = get_dns_events(limit=10000)

if dns_df.empty:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🔍</div>
        <div>No DNS telemetry stored in the system.</div>
        <div style="font-size:0.8rem;margin-top:0.25rem;">Generate sample data from Settings to populate.</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

with st.spinner("Analyzing DNS patterns…"):
    anomalies = detect_dns_anomalies(dns_df)

# ─── KPIs ─────────────────────────────────────────────────────────────────────
total_dns       = len(dns_df)
unique_doms     = dns_df["domain"].nunique()
long_doms       = sum(1 for a in anomalies if any(s["indicator_name"] == "long_domain"           for s in a.get("signals", [])))
high_freq_doms  = sum(1 for a in anomalies if any(s["indicator_name"] == "high_frequency_domain" for s in a.get("signals", [])))
rare_doms       = sum(1 for a in anomalies if any(s["indicator_name"] == "rare_domain"           for s in a.get("signals", [])))
subdom_tunnels  = sum(1 for a in anomalies if any(s["indicator_name"] == "excessive_subdomains"  for s in a.get("signals", [])))

k1, k2, k3, k4, k5, k6 = st.columns(6)
with k1: st.metric("Total DNS Queries",    f"{total_dns:,}")
with k2: st.metric("Unique Domains",       f"{unique_doms:,}")
with k3: st.metric("Total Anomalies",      f"{len(anomalies):,}")
with k4: st.metric("Long Domains (DGA)",   long_doms)
with k5: st.metric("High Frequency",       high_freq_doms)
with k6: st.metric("Subdomain Tunneling",  subdom_tunnels)

st.divider()

# ─── DNS query volume chart ───────────────────────────────────────────────────
section_heading("Top Queried Domains")
top_domains = dns_df["domain"].value_counts().head(15).reset_index()
top_domains.columns = ["domain", "query_count"]
fig_top = px.bar(
    top_domains, x="query_count", y="domain", orientation="h",
    color_discrete_sequence=[COLOR_LOW],
    labels={"query_count": "Query Count", "domain": "Domain"},
)
fig_top.update_layout(
    height=350,
    margin=dict(l=10, r=10, t=10, b=20),
    paper_bgcolor=COLOR_SURFACE,
    plot_bgcolor=COLOR_SURFACE,
    yaxis=dict(autorange="reversed"),
)
st.plotly_chart(fig_top, use_container_width=True)

st.divider()

# ─── Anomaly tabs ─────────────────────────────────────────────────────────────
t_long, t_freq, t_rare, t_sub, t_all = st.tabs([
    "📏 Long Domains (DGA)",
    "⚡ High Frequency",
    "🎯 Rare Domains",
    "🌿 Subdomain Tunneling",
    "📋 All Anomalies",
])

with t_long:
    section_heading("Long Domain Names (>50 chars)")
    long_rows = []
    for a in anomalies:
        for s in a.get("signals", []):
            if s["indicator_name"] == "long_domain":
                long_rows.append({
                    "source_ip":  a["source_ip"],
                    "domain":     a["domain"],
                    "length":     len(a["domain"]),
                    "risk_score": a["risk_score"]
                })
    if long_rows:
        ld_df = pd.DataFrame(long_rows).drop_duplicates().sort_values("length", ascending=False)
        st.dataframe(ld_df, use_container_width=True, hide_index=True)
        fig = px.bar(
            ld_df.head(20), x="length", y="domain", orientation="h",
            color="length",
            color_continuous_scale=[[0, COLOR_MEDIUM], [1, COLOR_CRITICAL]],
            labels={"length": "Domain Length", "domain": "Domain"},
        )
        fig.update_layout(height=300, paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
                          margin=dict(l=10, r=10, t=10, b=20), showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No long domain anomalies flagged.")

with t_freq:
    section_heading("High Frequency Domain Queries")
    freq_rows = []
    for a in anomalies:
        for s in a.get("signals", []):
            if s["indicator_name"] == "high_frequency_domain":
                freq_rows.append({
                    "source_ip":   a["source_ip"],
                    "domain":      a["domain"],
                    "query_count": a.get("query_count", 0),
                    "risk_score":  a["risk_score"]
                })
    if freq_rows:
        hf_df = pd.DataFrame(freq_rows).drop_duplicates().sort_values("query_count", ascending=False)
        st.dataframe(hf_df, use_container_width=True, hide_index=True)
    else:
        st.info("No high frequency domain anomalies flagged.")

with t_rare:
    section_heading("Rare Single-Host Domains")
    rare_rows = []
    for a in anomalies:
        for s in a.get("signals", []):
            if s["indicator_name"] == "rare_domain":
                rare_rows.append({
                    "source_ip":  a["source_ip"],
                    "domain":     a["domain"],
                    "detail":     s.get("detail", ""),
                    "risk_score": a["risk_score"]
                })
    if rare_rows:
        rd_df = pd.DataFrame(rare_rows).drop_duplicates()
        st.dataframe(rd_df, use_container_width=True, hide_index=True)
    else:
        st.info("No rare domain anomalies flagged.")

with t_sub:
    section_heading("Excessive Subdomain Labels (DNS Tunneling)")
    sub_rows = []
    for a in anomalies:
        for s in a.get("signals", []):
            if s["indicator_name"] == "excessive_subdomains":
                sub_rows.append({
                    "source_ip":       a["source_ip"],
                    "base_domain":     a["domain"],
                    "subdomain_count": s.get("value", 0),
                    "risk_score":      a["risk_score"]
                })
    if sub_rows:
        es_df = pd.DataFrame(sub_rows).drop_duplicates().sort_values("subdomain_count", ascending=False)
        st.dataframe(es_df, use_container_width=True, hide_index=True)
    else:
        st.info("No subdomain tunneling anomalies flagged.")

with t_all:
    section_heading("All DNS Anomalies")
    if anomalies:
        all_rows = []
        for a in anomalies:
            signal_names = [s["indicator_name"] for s in a.get("signals", [])]
            all_rows.append({
                "source_ip":  a["source_ip"],
                "domain":     a["domain"],
                "risk_score": a["risk_score"],
                "signals":    ", ".join(signal_names),
            })
        all_df = pd.DataFrame(all_rows).drop_duplicates().sort_values("risk_score", ascending=False)
        st.dataframe(all_df, use_container_width=True, hide_index=True)
    else:
        st.info("No DNS anomalies detected.")
