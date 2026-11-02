import os
import glob
from datetime import datetime, timezone
import streamlit as st
import pandas as pd

st.title("📁 Evidence Locker & Artifact Browser")
st.caption("Inspect raw PCAP captures, generated Zeek log batches, and exported JSON alerts")

ALLOWED_DIRS = ["data/raw", "data/zeek", "data/alerts"]

def get_file_type(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".pcap", ".pcapng"):
        return "Raw PCAP"
    elif ext == ".log":
        return "Zeek Log"
    elif ext == ".json":
        return "JSON Alert Evidence"
    return "Artifact"

def format_size(num_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"

file_records = []

for base_dir in ALLOWED_DIRS:
    if not os.path.exists(base_dir):
        continue
    for root, _, files in os.walk(base_dir):
        # Strict path traversal security check
        real_root = os.path.realpath(root)
        if not any(real_root.startswith(os.path.realpath(d)) for d in ALLOWED_DIRS):
            continue
            
        for f in files:
            if f == ".gitkeep":
                continue
            full_path = os.path.join(root, f)
            try:
                st_stat = os.stat(full_path)
                mtime = datetime.fromtimestamp(st_stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                file_records.append({
                    "Filename": f,
                    "Directory": root,
                    "Type": get_file_type(full_path),
                    "Size": format_size(st_stat.st_size),
                    "Created (UTC)": mtime,
                    "Path": full_path
                })
            except Exception:
                pass

if file_records:
    df_files = pd.DataFrame(file_records)
    st.write(f"Total Evidence Files Found: **{len(df_files)}**")
    
    type_filter = st.multiselect("Filter by File Type", options=["Raw PCAP", "Zeek Log", "JSON Alert Evidence"], default=["Raw PCAP", "Zeek Log", "JSON Alert Evidence"])
    filtered_df = df_files[df_files["Type"].isin(type_filter)]
    
    st.dataframe(filtered_df[["Filename", "Type", "Size", "Created (UTC)", "Directory"]], use_container_width=True, hide_index=True)
    
    st.divider()
    st.subheader("📄 File Preview (Read-Only)")
    selected_file = st.selectbox("Select file to preview first 50 lines", options=filtered_df["Path"].tolist())
    if selected_file:
        st.code(f"Viewing: {selected_file}", language="bash")
        if selected_file.endswith((".log", ".json", ".txt", ".yaml")):
            try:
                with open(selected_file, "r", encoding="utf-8", errors="replace") as f:
                    lines = [f.readline() for _ in range(50)]
                    st.text("".join(lines))
            except Exception as e:
                st.error(f"Error reading file preview: {e}")
        else:
            st.info("Binary PCAP file — packet inspection via Zeek pipeline or Scapy.")
else:
    st.info("No raw PCAPs, Zeek logs, or JSON evidence files found in data directories.")
