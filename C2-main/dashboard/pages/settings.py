import os
import streamlit as st
from src.utils.config_loader import load_app_config, load_detection_rules

st.title("⚙️ System Settings & Control Panel")
st.caption("Inspect active configuration, re-seed sample datasets, or perform database maintenance")

app_cfg = load_app_config()
rules_cfg = load_detection_rules()

c1, c2 = st.columns(2)

with c1:
    st.subheader("Application Configuration")
    st.json(app_cfg)

with c2:
    st.subheader("Detection Rules Summary")
    st.json(rules_cfg)

st.divider()
st.subheader("🛠️ Operational Actions")

act1, act2 = st.columns(2)

with act1:
    st.write("##### Load Synthetic Sample Dataset")
    st.caption("Populates SQLite database with ~1,000 synthetic network & DNS events including a beaconing C2 pair.")
    if st.button("Generate & Load Sample Data 🚀"):
        try:
            from scripts.generate_test_data import generate_all_test_data
            from src.services.pipeline import run_detection_only
            
            with st.spinner("Generating synthetic telemetry..."):
                counts = generate_all_test_data()
                alerts_n = run_detection_only()
                
            st.success(f"Sample dataset loaded! Inserted {counts['net_events']} network events, {counts['dns_events']} DNS events, and generated {alerts_n} alerts.")
            st.rerun()
        except Exception as e:
            st.error(f"Error generating sample dataset: {e}")

with act2:
    st.write("##### Reset Database")
    st.caption("Wipes all tables in SQLite database. Raw PCAP files and Zeek log archives will be preserved.")
    
    confirm_text = st.text_input("Type 'RESET' to confirm DB wipe:", value="")
    if st.button("Wipe & Re-initialize Database ⚠️", disabled=(confirm_text.strip() != "RESET")):
        try:
            from scripts.reset_db import reset_database
            reset_database(full=False)
            st.success("Database wiped and re-initialized successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Error resetting database: {e}")
