"""
MITRE ATT&CK Coverage Heatmap — NetSentry SOC
Maps all detected alert types to ATT&CK techniques,
shows technique frequency heatmap and per-technique alert breakdown.
"""
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from collections import defaultdict

from src.database.repositories import get_alerts
from src.services.mitre_mapping import get_mitre_context, load_mitre_mapping, DEFAULT_MITRE_MAPPING
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW,
    render_page_header, render_severity_badge, section_heading
)

render_page_header(
    "MITRE ATT&CK Coverage",
    "Technique heatmap derived from detected alerts — behavioral detection only",
    "⚔️"
)

# ─── Hedge disclaimer ─────────────────────────────────────────────────────────
st.markdown(f"""
<div style="background:rgba(216,137,85,0.07);border:1px solid rgba(216,137,85,0.25);
            border-radius:8px;padding:0.75rem 1.25rem;margin-bottom:1.25rem;
            font-size:0.82rem;color:{COLOR_TEXT_MUTED};">
    ⚠️ <strong style="color:{COLOR_ACCENT};">Behavioral attribution only.</strong>
    Techniques shown are potential mappings from observed behavioral patterns —
    they do not confirm attacker intent or confirm that the technique was used.
    Each detection rule maps to one or more ATT&amp;CK techniques as a starting point for investigation.
</div>
""", unsafe_allow_html=True)

# ─── Load alert data ──────────────────────────────────────────────────────────
alerts_df = get_alerts(limit=5000)

if alerts_df.empty:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">⚔️</div>
        <div style="font-weight:500;margin-bottom:0.25rem;">No alert data available</div>
        <div style="font-size:0.8rem;">
            Generate sample data from <strong>Settings → Operations</strong> or run the detection pipeline.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ─── Build technique frequency map ───────────────────────────────────────────
mitre_mapping = load_mitre_mapping()

# technique_id → {name, count, alert_types, severity_counts}
technique_stats: dict[str, dict] = {}

for _, row in alerts_df.iterrows():
    atype = str(row.get("alert_type", "")).upper()
    sev   = str(row.get("severity", "LOW")).upper()
    techs = get_mitre_context(atype)

    for t in techs:
        tid  = t["technique_id"]
        tname = t["name"]
        if tid not in technique_stats:
            technique_stats[tid] = {
                "name":            tname,
                "technique_id":    tid,
                "count":           0,
                "alert_types":     defaultdict(int),
                "severity_counts": defaultdict(int),
            }
        technique_stats[tid]["count"] += 1
        technique_stats[tid]["alert_types"][atype] += 1
        technique_stats[tid]["severity_counts"][sev] += 1

if not technique_stats:
    st.warning("No MITRE technique mappings found for current alerts.")
    st.stop()

# ─── KPIs ────────────────────────────────────────────────────────────────────
total_alerts  = len(alerts_df)
unique_techs  = len(technique_stats)
max_hits      = max(v["count"] for v in technique_stats.values())
top_tid       = max(technique_stats, key=lambda k: technique_stats[k]["count"])
top_tname     = technique_stats[top_tid]["name"]

k1, k2, k3, k4 = st.columns(4)
with k1: st.metric("Total Alerts",         f"{total_alerts:,}")
with k2: st.metric("Unique Techniques",    f"{unique_techs}")
with k3: st.metric("Alert Types Mapped",   f"{alerts_df['alert_type'].nunique()}")
with k4: st.metric("Top Technique",        top_tid, delta=top_tname, delta_color="off")

st.divider()

# ─── Heatmap chart ────────────────────────────────────────────────────────────
section_heading("Technique Frequency Heatmap")

# Pivot: alert_type × technique_id → hit count
all_atypes = sorted(alerts_df["alert_type"].unique().tolist())
all_tids   = sorted(technique_stats.keys())

heatmap_z    = []
heatmap_text = []

for tid in all_tids:
    row_z    = []
    row_text = []
    for at in all_atypes:
        count = technique_stats[tid]["alert_types"].get(at, 0)
        row_z.append(count)
        row_text.append(f"{tid}<br>{at}: {count}")
    heatmap_z.append(row_z)
    heatmap_text.append(row_text)

y_labels = [f"{tid} — {technique_stats[tid]['name']}" for tid in all_tids]

fig_heatmap = go.Figure(data=go.Heatmap(
    z=heatmap_z,
    x=all_atypes,
    y=y_labels,
    text=heatmap_text,
    hovertemplate="%{text}<extra></extra>",
    colorscale=[
        [0.0,  "rgba(18,24,35,1)"],
        [0.01, "rgba(216,137,85,0.15)"],
        [0.3,  "rgba(216,137,85,0.5)"],
        [0.7,  "rgba(216,137,85,0.8)"],
        [1.0,  "rgba(224,82,82,1)"],
    ],
    showscale=True,
    colorbar=dict(
        title="Alert Count",
        titlefont=dict(size=11),
        tickfont=dict(size=10),
    ),
    xgap=3,
    ygap=3,
))
fig_heatmap.update_layout(
    height=max(280, 60 * len(all_tids)),
    margin=dict(l=10, r=10, t=10, b=20),
    paper_bgcolor=COLOR_SURFACE,
    plot_bgcolor=COLOR_SURFACE,
    xaxis=dict(
        tickfont=dict(size=11, family="JetBrains Mono, monospace"),
        title="Alert Type",
    ),
    yaxis=dict(
        tickfont=dict(size=11),
        autorange="reversed",
    ),
    font=dict(color=COLOR_TEXT),
)
st.plotly_chart(fig_heatmap, use_container_width=True)

st.divider()

# ─── Bar chart — techniques by total alert count ──────────────────────────────
section_heading("Techniques by Alert Volume")

tech_df = pd.DataFrame([
    {
        "technique_id": tid,
        "name":         v["name"],
        "label":        f"{tid} — {v['name']}",
        "count":        v["count"],
        "critical":     v["severity_counts"].get("CRITICAL", 0),
        "high":         v["severity_counts"].get("HIGH", 0),
        "medium":       v["severity_counts"].get("MEDIUM", 0),
        "low":          v["severity_counts"].get("LOW", 0),
    }
    for tid, v in technique_stats.items()
]).sort_values("count", ascending=True)

fig_bar = go.Figure()
for sev_name, color in [
    ("critical", COLOR_CRITICAL),
    ("high",     COLOR_HIGH),
    ("medium",   COLOR_MEDIUM),
    ("low",      COLOR_LOW),
]:
    fig_bar.add_trace(go.Bar(
        y=tech_df["label"],
        x=tech_df[sev_name],
        name=sev_name.upper(),
        orientation="h",
        marker_color=color,
        hovertemplate=f"<b>%{{y}}</b><br>{sev_name.upper()}: %{{x}}<extra></extra>",
    ))

fig_bar.update_layout(
    barmode="stack",
    height=max(240, 56 * len(tech_df)),
    margin=dict(l=10, r=10, t=10, b=20),
    paper_bgcolor=COLOR_SURFACE,
    plot_bgcolor=COLOR_SURFACE,
    legend=dict(
        orientation="h",
        yanchor="bottom", y=1.02,
        xanchor="right",  x=1,
        font=dict(size=11),
    ),
    xaxis=dict(gridcolor=COLOR_BORDER_SUBTLE, title="Alert Count"),
    yaxis=dict(tickfont=dict(size=11)),
    font=dict(color=COLOR_TEXT),
)
st.plotly_chart(fig_bar, use_container_width=True)

st.divider()

# ─── Per-technique drilldown ──────────────────────────────────────────────────
section_heading("Technique Drilldown")

sorted_techs = sorted(technique_stats.items(), key=lambda x: -x[1]["count"])
selected_tech = st.selectbox(
    "Select Technique",
    options=[tid for tid, _ in sorted_techs],
    format_func=lambda tid: f"{tid} — {technique_stats[tid]['name']} ({technique_stats[tid]['count']} alerts)",
    label_visibility="collapsed",
)

if selected_tech:
    ts = technique_stats[selected_tech]
    att_url = f"https://attack.mitre.org/techniques/{selected_tech.replace('.', '/')}/"

    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                border-left:4px solid {COLOR_ACCENT};border-radius:10px;
                padding:1.1rem 1.5rem;margin-bottom:1rem;">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:1rem;">
            <div>
                <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.4rem;">
                    <code style="font-size:1rem;font-weight:700;color:{COLOR_ACCENT};
                                 background:{COLOR_ELEVATED};padding:0.2em 0.6em;border-radius:5px;">
                        {selected_tech}
                    </code>
                    <span style="font-size:1rem;font-weight:600;color:{COLOR_TEXT};">{ts['name']}</span>
                </div>
                <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};">
                    <a href="{att_url}" target="_blank" rel="noopener"
                       style="color:{COLOR_ACCENT};text-decoration:none;">
                        View on MITRE ATT&amp;CK →
                    </a>
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            font-weight:800;color:{COLOR_ACCENT};line-height:1;">
                    {ts['count']}
                </div>
                <div style="font-size:0.68rem;text-transform:uppercase;letter-spacing:0.1em;
                            color:{COLOR_TEXT_MUTED};font-weight:600;">Alert Hits</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Severity breakdown mini-bar
    sev_breakdown_cols = st.columns(4)
    for col, (sev, color) in zip(sev_breakdown_cols, [
        ("CRITICAL", COLOR_CRITICAL), ("HIGH", COLOR_HIGH),
        ("MEDIUM", COLOR_MEDIUM), ("LOW", COLOR_LOW)
    ]):
        with col:
            cnt = ts["severity_counts"].get(sev, 0)
            st.markdown(f"""
            <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                        border-top:3px solid {color};border-radius:7px;
                        padding:0.6rem 0.75rem;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.4rem;
                            font-weight:700;color:{color};line-height:1;">{cnt}</div>
                <div style="font-size:0.67rem;text-transform:uppercase;letter-spacing:0.08em;
                            color:{COLOR_TEXT_MUTED};margin-top:0.15rem;">{sev}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("<div style='height:0.75rem;'></div>", unsafe_allow_html=True)

    # Contributing alert types
    section_heading("Contributing Alert Types")
    for atype_name, cnt in sorted(ts["alert_types"].items(), key=lambda x: -x[1]):
        pct = cnt / ts["count"] * 100
        bar_width = max(4, int(pct))
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.35rem;">
            <code style="font-size:0.8rem;min-width:180px;color:{COLOR_TEXT};">{atype_name}</code>
            <div style="flex:1;background:{COLOR_ELEVATED};border-radius:4px;height:8px;overflow:hidden;">
                <div style="width:{bar_width}%;background:{COLOR_ACCENT};height:100%;border-radius:4px;"></div>
            </div>
            <span style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;
                         color:{COLOR_TEXT_MUTED};min-width:60px;text-align:right;">
                {cnt} ({pct:.0f}%)
            </span>
        </div>
        """, unsafe_allow_html=True)

    st.divider()

    # Sample alerts for this technique
    section_heading("Sample Alerts (up to 10)")
    matching_types = list(ts["alert_types"].keys())
    if matching_types:
        sample_alerts = alerts_df[alerts_df["alert_type"].isin(matching_types)].head(10)
        for _, row in sample_alerts.iterrows():
            sev = row.get("severity", "LOW").upper()
            sev_color_map = {
                "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
            }
            lb = sev_color_map.get(sev, COLOR_LOW)
            st.markdown(f"""
            <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                        border-left:3px solid {lb};border-radius:7px;
                        padding:0.65rem 1rem;margin-bottom:0.3rem;
                        display:flex;align-items:center;justify-content:space-between;">
                <div>
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.2rem;">
                        {render_severity_badge(sev)}
                        <code style="font-size:0.78rem;">{row['alert_type']}</code>
                        <span style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};">
                            Score: <strong style="color:{COLOR_ACCENT};">{row['risk_score']}</strong>
                        </span>
                    </div>
                    <div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};">
                        <code>{row['source_ip']}</code> → <code>{row['destination_ip']}</code>
                    </div>
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;
                            color:{COLOR_TEXT_MUTED};text-align:right;min-width:110px;">
                    {str(row.get('last_seen',''))[:16]}
                </div>
            </div>
            """, unsafe_allow_html=True)

# ─── Full mapping reference ───────────────────────────────────────────────────
with st.expander("📋  Full Alert-Type → Technique Mapping Reference", expanded=False):
    for atype, techs in DEFAULT_MITRE_MAPPING.items():
        st.markdown(f"""
        <div style="margin-bottom:0.75rem;">
            <code style="font-size:0.85rem;font-weight:600;color:{COLOR_TEXT};">{atype}</code>
        </div>
        """, unsafe_allow_html=True)
        for t in techs:
            att_url = f"https://attack.mitre.org/techniques/{t['technique_id'].replace('.', '/')}/"
            st.markdown(f"""
            <div style="margin-left:1rem;margin-bottom:0.3rem;font-size:0.8rem;
                        color:{COLOR_TEXT_MUTED};">
                <a href="{att_url}" target="_blank" rel="noopener"
                   style="color:{COLOR_ACCENT};text-decoration:none;font-weight:600;">
                    {t['technique_id']}
                </a>
                &nbsp;—&nbsp;{t['name']}
            </div>
            """, unsafe_allow_html=True)

