import streamlit as st
import plotly.express as px
import pandas as pd
from src.database.repositories import get_dns_events
from src.detection.dns_detection import detect_dns_anomalies
from dashboard.theme import COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_SAFE

st.title("🔍 DNS Anomaly & Tunneling Analysis")
st.caption("Deep inspection of domain query patterns, DGA indicators, and subdomain volume")

st.info("ℹ️ **Analysis Disclaimer**: These indicators contribute to investigation risk. They do not, individually or combined, constitute proof of malicious activity.")

dns_df = get_dns_events(limit=10000)

if dns_df.empty:
    st.info("No DNS telemetry stored in system.")
    st.stop()

anomalies = detect_dns_anomalies(dns_df)

# Compute DNS KPIs
total_dns = len(dns_df)
unique_doms = dns_df["domain"].nunique()

long_doms = sum(1 for a in anomalies if any(s["indicator_name"] == "long_domain" for s in a["signals"]))
high_freq_doms = sum(1 for a in anomalies if any(s["indicator_name"] == "high_frequency_domain" for s in a["signals"]))
rare_doms = sum(1 for a in anomalies if any(s["indicator_name"] == "rare_domain" for s in a["signals"]))
subdom_tunnels = sum(1 for a in anomalies if any(s["indicator_name"] == "excessive_subdomains" for s in a["signals"]))

k1, k2, k3, k4, k5 = st.columns(5)
with k1: st.metric("Total DNS Queries", f"{total_dns:,}")
with k2: st.metric("Unique Domains", f"{unique_doms:,}")
with k3: st.metric("Long Domains", long_doms)
with k4: st.metric("High Freq Domains", high_freq_doms)
with k5: st.metric("Subdomain Tunneling", subdom_tunnels)

st.divider()

t_long, t_freq, t_rare, t_sub = st.tabs([
    "Long Domains (DGA)",
    "High Frequency Domains",
    "Rare Domains",
    "Excessive Subdomains"
])

with t_long:
    st.subheader("Long Domain Names (>50 chars)")
    long_rows = []
    for a in anomalies:
        for s in a["signals"]:
            if s["indicator_name"] == "long_domain":
                long_rows.append({"source_ip": a["source_ip"], "domain": a["domain"], "length": len(a["domain"]), "risk_score": a["risk_score"]})
    if long_rows:
        ld_df = pd.DataFrame(long_rows).drop_duplicates()
        st.dataframe(ld_df, use_container_width=True, hide_index=True)
        fig = px.bar(ld_df, x="length", y="domain", orientation="h", color_discrete_sequence=[COLOR_HIGH])
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No long domain anomalies flagged.")

with t_freq:
    st.subheader("High Frequency Domain Queries")
    freq_rows = []
    for a in anomalies:
        for s in a["signals"]:
            if s["indicator_name"] == "high_frequency_domain":
                freq_rows.append({"source_ip": a["source_ip"], "domain": a["domain"], "query_count": a["query_count"]})
    if freq_rows:
        hf_df = pd.DataFrame(freq_rows).drop_duplicates()
        st.dataframe(hf_df, use_container_width=True, hide_index=True)
    else:
        st.info("No high frequency domain anomalies flagged.")

with t_rare:
    st.subheader("Rare Single-Host Domains")
    rare_rows = []
    for a in anomalies:
        for s in a["signals"]:
            if s["indicator_name"] == "rare_domain":
                rare_rows.append({"source_ip": a["source_ip"], "domain": a["domain"], "detail": s["detail"]})
    if rare_rows:
        rd_df = pd.DataFrame(rare_rows).drop_duplicates()
        st.dataframe(rd_df, use_container_width=True, hide_index=True)
    else:
        st.info("No rare domain anomalies flagged.")

with t_sub:
    st.subheader("Excessive Subdomain Labels (Tunneling)")
    sub_rows = []
    for a in anomalies:
        for s in a["signals"]:
            if s["indicator_name"] == "excessive_subdomains":
                sub_rows.append({"source_ip": a["source_ip"], "base_domain": a["domain"], "subdomain_count": s["value"]})
    if sub_rows:
        es_df = pd.DataFrame(sub_rows).drop_duplicates()
        st.dataframe(es_df, use_container_width=True, hide_index=True)
    else:
        st.info("No excessive subdomain tunneling anomalies flagged.")
