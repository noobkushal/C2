import os
from datetime import datetime, timezone
import streamlit as st
import pandas as pd
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW,
    render_page_header, section_heading
)

render_page_header(
    "Evidence Locker & Artifact Browser",
    "Inspect raw PCAP captures, exported JSON alerts, and forensic artifacts",
    "🗂️"
)

ALLOWED_DIRS = ["data/raw", "data/zeek", "data/alerts"]

def get_file_type(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".pcap", ".pcapng"): return "Raw PCAP"
    elif ext == ".log":             return "Zeek Log"
    elif ext == ".json":            return "JSON Evidence"
    elif ext == ".csv":             return "CSV Export"
    return "Artifact"

def format_size(num_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"

type_colors = {
    "Raw PCAP":    COLOR_CRITICAL,
    "Zeek Log":    COLOR_SAFE,
    "JSON Evidence": COLOR_ACCENT,
    "CSV Export":  COLOR_LOW,
    "Artifact":    COLOR_TEXT_MUTED,
}

# ─── Scan files ───────────────────────────────────────────────────────────────
file_records = []
for base_dir in ALLOWED_DIRS:
    if not os.path.exists(base_dir):
        continue
    for root, _, files in os.walk(base_dir):
        real_root = os.path.realpath(root)
        if not any(real_root.startswith(os.path.realpath(d)) for d in ALLOWED_DIRS):
            continue
        for f in files:
            if f == ".gitkeep":
                continue
            full_path = os.path.join(root, f)
            try:
                st_stat = os.stat(full_path)
                mtime   = datetime.fromtimestamp(st_stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                file_records.append({
                    "Filename":      f,
                    "Directory":     root,
                    "Type":          get_file_type(full_path),
                    "Size":          format_size(st_stat.st_size),
                    "Created (UTC)": mtime,
                    "Path":          full_path,
                    "_size_bytes":   st_stat.st_size,
                })
            except Exception:
                pass

# ─── Summary KPIs ─────────────────────────────────────────────────────────────
if file_records:
    df_files    = pd.DataFrame(file_records)
    total_files = len(df_files)
    total_size  = format_size(df_files["_size_bytes"].sum())
    pcap_count  = len(df_files[df_files["Type"] == "Raw PCAP"])
    json_count  = len(df_files[df_files["Type"] == "JSON Evidence"])

    k1, k2, k3, k4 = st.columns(4)
    with k1: st.metric("Total Artifacts",    total_files)
    with k2: st.metric("Total Size",         total_size)
    with k3: st.metric("PCAP Files",         pcap_count)
    with k4: st.metric("JSON Evidence",      json_count)

    st.divider()

    # ─── File type filter ─────────────────────────────────────────────────────
    section_heading("Artifact Browser")
    type_options = sorted(df_files["Type"].unique().tolist())
    type_filter  = st.multiselect(
        "Filter by Type",
        options=type_options,
        default=type_options,
    )
    filtered_df = df_files[df_files["Type"].isin(type_filter)]

    # Render as styled cards
    for _, row in filtered_df.iterrows():
        ftype  = row["Type"]
        fcolor = type_colors.get(ftype, COLOR_TEXT_MUTED)
        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-left:3px solid {fcolor};border-radius:7px;
                    padding:0.75rem 1.25rem;margin-bottom:0.4rem;
                    display:flex;align-items:center;justify-content:space-between;">
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;
                             color:{COLOR_TEXT};font-weight:500;">{row['Filename']}</div>
                <div style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};margin-top:0.15rem;">
                    {row['Directory']}
                </div>
            </div>
            <div style="text-align:right;min-width:180px;">
                <div style="display:inline-block;background:rgba(255,255,255,0.04);
                             border:1px solid {fcolor}44;border-radius:4px;
                             padding:0.1em 0.5em;font-size:0.7rem;font-weight:600;
                             color:{fcolor};text-transform:uppercase;letter-spacing:0.05em;">
                    {ftype}
                </div>
                <div style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};margin-top:0.2rem;">
                    {row['Size']} · {row['Created (UTC)'][:16]}
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # ─── File preview ─────────────────────────────────────────────────────────
    section_heading("File Preview (Read-Only)")
    path_options = filtered_df["Path"].tolist()
    if path_options:
        selected_file = st.selectbox(
            "Select file to preview",
            options=path_options,
            format_func=lambda p: os.path.basename(p),
        )
        if selected_file:
            ext = os.path.splitext(selected_file)[1].lower()
            if ext in (".log", ".json", ".txt", ".yaml", ".csv"):
                try:
                    with open(selected_file, "r", encoding="utf-8", errors="replace") as fh:
                        content = "".join(fh.readline() for _ in range(80))
                    lang = "json" if ext == ".json" else "bash"
                    st.code(content, language=lang)
                except Exception as e:
                    st.error(f"Error reading file: {e}")
            else:
                st.info("Binary file (PCAP/PCAPNG) — use Wireshark or the PCAP Analysis page to inspect.")

            # Download button for JSON/CSV
            if ext in (".json", ".csv"):
                try:
                    with open(selected_file, "rb") as fh:
                        content_bytes = fh.read()
                    mime = "application/json" if ext == ".json" else "text/csv"
                    st.download_button(
                        "📥  Download This File",
                        data=content_bytes,
                        file_name=os.path.basename(selected_file),
                        mime=mime,
                    )
                except Exception:
                    pass
else:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🗂️</div>
        <div style="font-weight:500;margin-bottom:0.25rem;">Evidence Locker is Empty</div>
        <div style="font-size:0.8rem;">
            Generate reports or capture traffic to create artifacts in <code>data/raw/</code>,
            <code>data/alerts/</code>, and <code>data/zeek/</code>.
        </div>
    </div>
    """, unsafe_allow_html=True)
