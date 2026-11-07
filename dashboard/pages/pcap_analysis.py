"""
PCAP Analysis Page — NetSentry SOC
Upload a PCAP/PCAPNG file, parse packets, view statistics, and optionally
ingest events into the database to run the full detection pipeline.
"""
import os
import io
import uuid
import struct
import tempfile
from datetime import datetime, timezone

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BORDER,
    render_page_header, render_severity_badge, section_heading
)

render_page_header(
    "PCAP Analysis",
    "Upload a packet capture file to parse, visualize, and ingest traffic into the detection pipeline",
    "📦"
)

# ─── Scapy availability check ─────────────────────────────────────────────────
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

# ─── Constants ────────────────────────────────────────────────────────────────
UPLOAD_DIR   = "data/raw"
MAX_PCAP_MB  = 50
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ─── Scapy status banner ──────────────────────────────────────────────────────
if not HAS_SCAPY:
    st.markdown(f"""
    <div style="background:rgba(255,193,7,0.08);border:1px solid rgba(255,193,7,0.30);
                border-radius:8px;padding:0.85rem 1.25rem;margin-bottom:1rem;
                display:flex;align-items:center;gap:0.75rem;">
        <span style="font-size:1.1rem;">⚠️</span>
        <div>
            <strong style="color:#FFC107;">Scapy not installed</strong>
            <span style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};margin-left:0.5rem;">—
                Deep packet parsing unavailable. Only basic PCAP header statistics will be shown.
                Install with <code>pip install scapy</code> for full analysis.
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ─── Upload widget ────────────────────────────────────────────────────────────
section_heading("Upload PCAP File")

col_up, col_info = st.columns([3, 1])
with col_up:
    uploaded = st.file_uploader(
        "Upload PCAP or PCAPNG file",
        type=["pcap", "pcapng"],
        accept_multiple_files=False,
        label_visibility="collapsed",
        help=f"Maximum file size: {MAX_PCAP_MB} MB. Supports libpcap (.pcap) and Next-Gen PCAP (.pcapng) formats."
    )
with col_info:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:0.75rem 1rem;font-size:0.78rem;color:{COLOR_TEXT_MUTED};
                height:100%;display:flex;flex-direction:column;justify-content:center;">
        <div style="margin-bottom:0.3rem;">📦 <strong style="color:{COLOR_TEXT};">Supported formats</strong></div>
        <div>· libpcap (.pcap)</div>
        <div>· PCAPNG (.pcapng)</div>
        <div style="margin-top:0.4rem;">Max size: <strong>{MAX_PCAP_MB} MB</strong></div>
    </div>
    """, unsafe_allow_html=True)

# ─── Show previously saved PCAPs ──────────────────────────────────────────────
saved_pcaps = [
    f for f in os.listdir(UPLOAD_DIR)
    if f.lower().endswith((".pcap", ".pcapng"))
]
if saved_pcaps and not uploaded:
    with st.expander(f"📂  Previously Uploaded PCAPs ({len(saved_pcaps)} files)", expanded=False):
        for fn in sorted(saved_pcaps, reverse=True):
            fp = os.path.join(UPLOAD_DIR, fn)
            size_kb = os.path.getsize(fp) // 1024
            col_fn, col_sz, col_btn = st.columns([4, 1, 1])
            with col_fn:
                st.markdown(f"<code style='font-size:0.82rem;'>{fn}</code>", unsafe_allow_html=True)
            with col_sz:
                st.markdown(f"<span style='font-size:0.78rem;color:{COLOR_TEXT_MUTED};'>{size_kb} KB</span>", unsafe_allow_html=True)
            with col_btn:
                if st.button("Analyze", key=f"saved_{fn}", use_container_width=True):
                    st.session_state["pcap_saved_path"] = fp
                    st.rerun()

# ─── Determine which file to analyze ──────────────────────────────────────────
pcap_path = None

if uploaded:
    file_size_mb = len(uploaded.getvalue()) / (1024 * 1024)
    if file_size_mb > MAX_PCAP_MB:
        st.error(f"File too large ({file_size_mb:.1f} MB). Maximum allowed is {MAX_PCAP_MB} MB.")
        st.stop()

    # Save to disk
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in uploaded.name)
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(save_path, "wb") as fh:
        fh.write(uploaded.getvalue())

    pcap_path = save_path
    pcap_bytes = uploaded.getvalue()
    st.session_state["pcap_saved_path"] = save_path
    st.success(f"✅ Uploaded and saved: `{save_path}` ({file_size_mb:.2f} MB)")

elif st.session_state.get("pcap_saved_path"):
    pcap_path = st.session_state["pcap_saved_path"]
    if not os.path.exists(pcap_path):
        st.warning("Previously selected PCAP file no longer exists. Please upload a new file.")
        st.session_state.pop("pcap_saved_path", None)
        st.stop()
    with open(pcap_path, "rb") as fh:
        pcap_bytes = fh.read()

if not pcap_path:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">📦</div>
        <div style="font-weight:500;margin-bottom:0.25rem;">Upload a PCAP file to begin analysis</div>
        <div style="font-size:0.8rem;">
            Drag-and-drop a <code>.pcap</code> or <code>.pcapng</code> capture file above.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Parse PCAP ───────────────────────────────────────────────────────────────
st.divider()

@st.cache_data(show_spinner=False, max_entries=5)
def parse_pcap_scapy(file_bytes: bytes) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Parse PCAP using Scapy. Returns (packets_df, dns_df, stats_dict)."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    packets    = rdpcap(tmp_path)
    os.unlink(tmp_path)

    rows     = []
    dns_rows = []

    for pkt in packets:
        if IP not in pkt:
            continue
        ip   = pkt[IP]
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
        sport = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport) if UDP in pkt else None
        dport = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport) if UDP in pkt else None
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        rows.append({
            "timestamp":       ts,
            "source_ip":       str(ip.src),
            "destination_ip":  str(ip.dst),
            "source_port":     sport,
            "destination_port": dport,
            "protocol":        proto,
            "length":          len(pkt),
            "ttl":             ip.ttl,
        })

        if DNS in pkt and DNSQR in pkt:
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                dns_rows.append({
                    "timestamp":  ts,
                    "source_ip":  str(ip.src),
                    "domain":     qname,
                    "query_type": "A",
                })
            except Exception:
                pass

    packets_df = pd.DataFrame(rows)
    dns_df     = pd.DataFrame(dns_rows)

    stats = {
        "total_packets":   len(packets),
        "ip_packets":      len(packets_df),
        "dns_queries":     len(dns_df),
        "unique_src_ips":  packets_df["source_ip"].nunique()   if not packets_df.empty else 0,
        "unique_dst_ips":  packets_df["destination_ip"].nunique() if not packets_df.empty else 0,
        "total_bytes":     packets_df["length"].sum()          if not packets_df.empty else 0,
        "protocols":       packets_df["protocol"].value_counts().to_dict() if not packets_df.empty else {},
    }
    return packets_df, dns_df, stats


@st.cache_data(show_spinner=False, max_entries=5)
def parse_pcap_basic(file_bytes: bytes) -> dict:
    """Basic PCAP header stats without Scapy (libpcap format only)."""
    try:
        magic = struct.unpack("<I", file_bytes[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            return {"error": "Not a valid libpcap file (PCAPNG not supported without Scapy)"}
        big_endian = magic in (0xD4C3B2A1, 0x4D3CB2A1)
        endian = ">" if big_endian else "<"
        _, _, _, _, _, snaplen, link_type = struct.unpack(endian + "IHHiIII", file_bytes[:24])
        packet_count = 0
        total_bytes  = 0
        offset = 24
        while offset + 16 <= len(file_bytes):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", file_bytes[offset:offset + 16])
            if incl_len > snaplen or incl_len > 65535:
                break
            packet_count += 1
            total_bytes  += orig_len
            offset += 16 + incl_len
        return {
            "total_packets": packet_count,
            "total_bytes":   total_bytes,
            "link_type":     link_type,
            "snaplen":       snaplen,
        }
    except Exception as e:
        return {"error": str(e)}


with st.spinner("Parsing PCAP file…"):
    if HAS_SCAPY:
        try:
            packets_df, dns_df, stats = parse_pcap_scapy(pcap_bytes)
            parse_error = None
        except Exception as e:
            parse_error = str(e)
            packets_df = pd.DataFrame()
            dns_df     = pd.DataFrame()
            stats      = {}
    else:
        basic_stats = parse_pcap_basic(pcap_bytes)
        packets_df  = pd.DataFrame()
        dns_df      = pd.DataFrame()
        parse_error = basic_stats.get("error")
        stats = basic_stats

if parse_error:
    st.error(f"Failed to parse PCAP: `{parse_error}`")
    st.stop()

# ─── Summary KPI row ──────────────────────────────────────────────────────────
section_heading("Capture Summary")

fname = os.path.basename(pcap_path)
pcap_size_kb = len(pcap_bytes) // 1024

st.markdown(f"""
<div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
            border-radius:8px;padding:0.85rem 1.25rem;margin-bottom:1rem;
            display:flex;align-items:center;gap:0.75rem;">
    <span style="font-size:1.1rem;">📦</span>
    <div>
        <code style="font-size:0.9rem;font-weight:600;color:{COLOR_TEXT};">{fname}</code>
        <span style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-left:0.75rem;">{pcap_size_kb:,} KB</span>
    </div>
</div>
""", unsafe_allow_html=True)

k_cols = st.columns(5 if HAS_SCAPY else 3)
with k_cols[0]: st.metric("Total Packets",  f"{stats.get('total_packets', 0):,}")
with k_cols[1]: st.metric("Total Bytes",    f"{stats.get('total_bytes', 0):,}")

if HAS_SCAPY:
    with k_cols[2]: st.metric("IP Packets",       f"{stats.get('ip_packets', 0):,}")
    with k_cols[3]: st.metric("DNS Queries",       f"{stats.get('dns_queries', 0):,}")
    with k_cols[4]: st.metric("Unique Source IPs", f"{stats.get('unique_src_ips', 0):,}")
else:
    with k_cols[2]:
        lt = stats.get("link_type", "?")
        link_labels = {1: "Ethernet", 105: "IEEE 802.11 (WiFi)", 0: "Loopback"}
        st.metric("Link Type", link_labels.get(lt, f"Type {lt}"))

if not HAS_SCAPY:
    st.info(
        "Install Scapy (`pip install scapy`) for full packet-level analysis: "
        "IP conversations, protocol breakdown, DNS queries, and timeline charts."
    )
    st.stop()

if packets_df.empty:
    st.warning("No IP-layer packets found in this capture. The file may contain only Layer 2 frames or be empty.")
    st.stop()

# ─── Charts ───────────────────────────────────────────────────────────────────
st.divider()
section_heading("Traffic Visualizations")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    section_heading("Protocol Distribution")
    proto_data = packets_df["protocol"].value_counts().reset_index()
    proto_data.columns = ["protocol", "count"]
    proto_colors = [COLOR_ACCENT, COLOR_LOW, COLOR_SAFE, COLOR_MEDIUM, COLOR_HIGH, COLOR_CRITICAL]
    fig_proto = px.pie(
        proto_data, names="protocol", values="count",
        color_discrete_sequence=proto_colors,
        hole=0.5,
    )
    fig_proto.update_traces(textposition="outside", textinfo="label+percent")
    fig_proto.update_layout(
        height=280, margin=dict(l=10, r=10, t=20, b=20),
        paper_bgcolor=COLOR_SURFACE, showlegend=False,
    )
    st.plotly_chart(fig_proto, use_container_width=True)

with chart_col2:
    section_heading("Top 10 Destination Ports")
    if "destination_port" in packets_df.columns:
        port_data = (
            packets_df["destination_port"].dropna().astype(int)
            .value_counts().head(10).reset_index()
        )
        port_data.columns = ["port", "count"]
        port_data["port"] = port_data["port"].astype(str)
        fig_ports = px.bar(
            port_data, x="port", y="count",
            color_discrete_sequence=[COLOR_LOW],
            labels={"port": "Destination Port", "count": "Packets"},
        )
        fig_ports.update_layout(
            height=280, margin=dict(l=10, r=10, t=10, b=20),
            paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
        )
        st.plotly_chart(fig_ports, use_container_width=True)

# Timeline chart (full width)
section_heading("Packet Timeline")
try:
    packets_df["dt"] = pd.to_datetime(packets_df["timestamp"], errors="coerce")
    packets_df = packets_df.dropna(subset=["dt"])
    duration_secs = (packets_df["dt"].max() - packets_df["dt"].min()).total_seconds()
    resample_rule = "1s" if duration_secs < 120 else "5s" if duration_secs < 600 else "1min"
    timeline_df = packets_df.set_index("dt").resample(resample_rule).size().reset_index(name="packets")

    fig_tl = go.Figure()
    fig_tl.add_trace(go.Scatter(
        x=timeline_df["dt"], y=timeline_df["packets"],
        mode="lines", line=dict(color=COLOR_ACCENT, width=2),
        fill="tozeroy", fillcolor="rgba(216,137,85,0.08)",
        hovertemplate="<b>%{x}</b><br>Packets: %{y}<extra></extra>"
    ))
    fig_tl.update_layout(
        height=240, margin=dict(l=10, r=10, t=10, b=20),
        paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
        xaxis=dict(gridcolor=COLOR_BORDER_SUBTLE),
        yaxis=dict(gridcolor=COLOR_BORDER_SUBTLE),
        showlegend=False,
    )
    st.plotly_chart(fig_tl, use_container_width=True)
except Exception:
    st.info("Could not render timeline (timestamps may be malformed).")

# Top talkers (side by side)
st.divider()
talk_col1, talk_col2 = st.columns(2)

with talk_col1:
    section_heading("Top 10 Source IPs (by Packet Count)")
    top_src = packets_df["source_ip"].value_counts().head(10).reset_index()
    top_src.columns = ["source_ip", "packets"]
    fig_src = px.bar(
        top_src, x="packets", y="source_ip", orientation="h",
        color_discrete_sequence=[COLOR_MEDIUM],
        labels={"packets": "Packets", "source_ip": "Source IP"},
    )
    fig_src.update_layout(
        yaxis=dict(autorange="reversed"),
        height=300, margin=dict(l=10, r=10, t=10, b=20),
        paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
    )
    st.plotly_chart(fig_src, use_container_width=True)

with talk_col2:
    section_heading("Top 10 Destination IPs (by Packet Count)")
    top_dst = packets_df["destination_ip"].value_counts().head(10).reset_index()
    top_dst.columns = ["destination_ip", "packets"]
    fig_dst = px.bar(
        top_dst, x="packets", y="destination_ip", orientation="h",
        color_discrete_sequence=[COLOR_LOW],
        labels={"packets": "Packets", "destination_ip": "Destination IP"},
    )
    fig_dst.update_layout(
        yaxis=dict(autorange="reversed"),
        height=300, margin=dict(l=10, r=10, t=10, b=20),
        paper_bgcolor=COLOR_SURFACE, plot_bgcolor=COLOR_SURFACE,
    )
    st.plotly_chart(fig_dst, use_container_width=True)

# ─── Tabbed detail tables ──────────────────────────────────────────────────────
st.divider()
section_heading("Packet Details")

tab_pkts, tab_dns, tab_conv = st.tabs([
    "🌐 Packets",
    "🔍 DNS Queries",
    "🔗 Top Conversations",
])

with tab_pkts:
    display_cols = [c for c in ["timestamp","source_ip","destination_ip",
                                 "destination_port","protocol","length","ttl"]
                    if c in packets_df.columns]
    st.dataframe(
        packets_df[display_cols].sort_values("timestamp", ascending=False),
        use_container_width=True,
        hide_index=True,
        height=360,
    )

with tab_dns:
    if not dns_df.empty:
        st.dataframe(
            dns_df.sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True,
            height=360,
        )
    else:
        st.markdown(f"""
        <div style="padding:2rem;text-align:center;color:{COLOR_TEXT_MUTED};font-size:0.88rem;">
            No DNS queries found in this capture.
        </div>
        """, unsafe_allow_html=True)

with tab_conv:
    # Top conversations = src_ip + dst_ip pairs by packet count
    conv_df = (
        packets_df.groupby(["source_ip", "destination_ip"])
        .agg(packets=("length", "count"), bytes=("length", "sum"))
        .reset_index()
        .sort_values("packets", ascending=False)
        .head(25)
    )
    st.dataframe(conv_df, use_container_width=True, hide_index=True, height=360)

# ─── Ingest into DB / run detection ───────────────────────────────────────────
st.divider()
section_heading("Ingest into Detection Pipeline")

st.markdown(f"""
<div style="font-size:0.83rem;color:{COLOR_TEXT_MUTED};margin-bottom:1rem;">
    Save parsed packets as <code>NetworkEvent</code> rows in the database and run the full
    detection pipeline (beacon detection, DNS anomaly, connection frequency, etc.) against this capture.
</div>
""", unsafe_allow_html=True)

ing_col1, ing_col2 = st.columns([2, 1])
with ing_col1:
    max_ingest = st.slider(
        "Max packets to ingest",
        min_value=100, max_value=min(50_000, len(packets_df)),
        value=min(5000, len(packets_df)),
        step=100,
        help="Ingesting very large captures can take several seconds."
    )
with ing_col2:
    ingest_btn = st.button(
        f"🚀  Ingest & Run Detection ({max_ingest:,} pkts)",
        type="primary",
        use_container_width=True,
    )

if ingest_btn:
    try:
        from src.database.database import get_db_connection, _db_lock
        from src.database.models import NetworkEvent as NetEvt, DNSEvent as DnsEvt
        from src.services.pipeline import run_detection_only
        from src.utils.time_utils import current_iso8601

        subset = packets_df.head(max_ingest)
        net_events_inserted = 0
        dns_events_inserted = 0

        with st.spinner(f"Inserting {max_ingest:,} network events…"):
            for _, row in subset.iterrows():
                evt_id = str(uuid.uuid4())
                with _db_lock:
                    conn = get_db_connection()
                    conn.cursor().execute(
                        """INSERT OR IGNORE INTO network_events
                           (event_id, timestamp, source_ip, source_port, destination_ip,
                            destination_port, protocol, bytes_sent, log_source)
                           VALUES (?,?,?,?,?,?,?,?,?)""",
                        (
                            evt_id,
                            row.get("timestamp", current_iso8601()),
                            row.get("source_ip", ""),
                            int(row["source_port"]) if pd.notna(row.get("source_port")) else None,
                            row.get("destination_ip", ""),
                            int(row["destination_port"]) if pd.notna(row.get("destination_port")) else None,
                            row.get("protocol", "ip").lower(),
                            int(row.get("length", 0)),
                            "pcap_upload",
                        )
                    )
                    conn.commit()
                    conn.close()
                net_events_inserted += 1

        if not dns_df.empty:
            with st.spinner("Inserting DNS events…"):
                for _, row in dns_df.iterrows():
                    evt_id = str(uuid.uuid4())
                    with _db_lock:
                        conn = get_db_connection()
                        conn.cursor().execute(
                            """INSERT OR IGNORE INTO dns_events
                               (event_id, timestamp, source_ip, domain, query_type)
                               VALUES (?,?,?,?,?)""",
                            (
                                evt_id,
                                row.get("timestamp", current_iso8601()),
                                row.get("source_ip", ""),
                                row.get("domain", ""),
                                row.get("query_type", "A"),
                            )
                        )
                        conn.commit()
                        conn.close()
                    dns_events_inserted += 1

        with st.spinner("Running detection pipeline…"):
            alerts_generated = run_detection_only()

        st.success(
            f"✅ Ingested **{net_events_inserted:,}** network events, "
            f"**{dns_events_inserted:,}** DNS events — "
            f"**{alerts_generated}** new alerts generated."
        )
        st.info("View detected threats in the **Alerts** or **C2 Detection** pages.")

    except Exception as e:
        import traceback
        st.error(f"Ingestion error: {e}")
        st.code(traceback.format_exc())

# ─── Quick-link to IP Investigation ──────────────────────────────────────────
if not packets_df.empty:
    st.divider()
    section_heading("Quick Pivot")
    top_src_ips = packets_df["source_ip"].value_counts().head(5).index.tolist()

    st.markdown(f"""
    <div style="font-size:0.82rem;color:{COLOR_TEXT_MUTED};margin-bottom:0.5rem;">
        Click any IP to open the IP Investigation workspace pre-loaded with this address.
    </div>
    """, unsafe_allow_html=True)

    pivot_cols = st.columns(min(5, len(top_src_ips)))
    for i, ip in enumerate(top_src_ips):
        with pivot_cols[i]:
            if st.button(f"🎯 {ip}", key=f"pivot_{ip}", use_container_width=True):
                st.session_state["investigate_ip"]  = ip
                st.session_state["current_page"]    = "IP Investigation"
                st.rerun()

