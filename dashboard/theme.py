import streamlit as st
import plotly.io as pio
import plotly.graph_objects as go

# ─── NetSentry Design Tokens ─────────────────────────────────────────────────
COLOR_BG        = "#0D0E10"      # Primary canvas background
COLOR_SURFACE   = "#17191C"      # Card / panel surface
COLOR_ELEVATED  = "#202327"      # Elevated / raised elements
COLOR_HOVER     = "#252A30"      # Hover state surface
COLOR_BORDER    = "#394047"      # Standard border
COLOR_BORDER_SUBTLE = "#2A2F35"  # Subtle border

COLOR_TEXT      = "#D4D9DF"      # Primary text
COLOR_TEXT_SEC  = "#999EA5"      # Secondary text
COLOR_TEXT_MUTED= "#798690"      # Muted / placeholder text

COLOR_ACCENT    = "#D88955"      # Warm orange primary accent
COLOR_ACCENT_DIM= "#A8652F"      # Dimmed accent

# Severity palette
COLOR_CRITICAL  = "#E05252"      # Muted red
COLOR_HIGH      = "#D88955"      # Warm orange
COLOR_MEDIUM    = "#C9A94D"      # Muted yellow
COLOR_LOW       = "#5C8FBE"      # Muted blue
COLOR_SAFE      = "#4BAF82"      # Muted green
COLOR_INFO      = "#64748B"      # Slate

SEVERITY_COLORS = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH":     COLOR_HIGH,
    "MEDIUM":   COLOR_MEDIUM,
    "LOW":      COLOR_LOW,
    "INFO":     COLOR_INFO,
    "SAFE":     COLOR_SAFE,
}

# Legacy aliases (used by older pages)
COLOR_CANVAS        = COLOR_BG
COLOR_RAISED        = COLOR_ELEVATED
COLOR_DRAWER        = COLOR_ELEVATED
COLOR_BORDER_STRONG = COLOR_BORDER

NETSENTRY_CSS = f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    /* ── Reset & Base ─────────────────────────────── */
    html, body, [class*="css"] {{
        font-family: 'Inter', sans-serif;
        background-color: {COLOR_BG};
        color: {COLOR_TEXT};
    }}

    .stApp {{
        background-color: {COLOR_BG};
        background-image: radial-gradient(circle, {COLOR_BORDER_SUBTLE} 1px, transparent 1px);
        background-size: 28px 28px;
    }}

    /* ── Main Content Area ────────────────────────── */
    .main .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }}

    /* ── Sidebar ──────────────────────────────────── */
    [data-testid="stSidebar"] {{
        background-color: {COLOR_SURFACE};
        border-right: 1px solid {COLOR_BORDER_SUBTLE};
    }}

    [data-testid="stSidebar"] .stMarkdown h1,
    [data-testid="stSidebar"] .stMarkdown h2,
    [data-testid="stSidebar"] .stMarkdown h3 {{
        color: {COLOR_TEXT};
    }}

    /* Sidebar radio buttons */
    [data-testid="stSidebar"] [data-testid="stRadio"] label {{
        font-size: 0.88rem;
        color: {COLOR_TEXT_SEC};
        padding: 0.4rem 0.8rem;
        border-radius: 5px;
        transition: all 0.15s ease;
    }}
    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {{
        color: {COLOR_TEXT};
        background: {COLOR_ELEVATED};
    }}
    [data-testid="stSidebar"] [data-testid="stRadio"] [aria-checked="true"] + label {{
        color: {COLOR_ACCENT};
        font-weight: 600;
    }}

    /* ── Headings ─────────────────────────────────── */
    h1 {{
        font-family: 'Inter', sans-serif;
        font-size: 1.65rem;
        font-weight: 700;
        color: {COLOR_TEXT};
        letter-spacing: -0.02em;
        margin-bottom: 0.15rem;
    }}
    h2, h3 {{
        font-family: 'Inter', sans-serif;
        font-weight: 600;
        color: {COLOR_TEXT};
        letter-spacing: -0.01em;
    }}
    h4, h5, h6 {{
        font-family: 'Inter', sans-serif;
        font-weight: 500;
        color: {COLOR_TEXT_SEC};
    }}

    /* ── Metric Cards ─────────────────────────────── */
    [data-testid="metric-container"] {{
        background: {COLOR_SURFACE};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-left: 3px solid {COLOR_ACCENT};
        border-radius: 8px;
        padding: 1rem 1.25rem !important;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }}
    [data-testid="metric-container"]:hover {{
        border-left-color: {COLOR_ACCENT};
        box-shadow: 0 0 0 1px {COLOR_BORDER}, 0 4px 16px rgba(0,0,0,0.3);
    }}

    [data-testid="stMetricValue"] {{
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 600 !important;
        font-size: 1.75rem !important;
        color: {COLOR_TEXT} !important;
        letter-spacing: -0.02em;
    }}

    [data-testid="stMetricLabel"] {{
        font-family: 'Inter', sans-serif !important;
        font-size: 0.72rem !important;
        color: {COLOR_TEXT_MUTED} !important;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 500;
    }}

    [data-testid="stMetricDelta"] {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.78rem !important;
    }}

    /* ── DataFrames / Tables ──────────────────────── */
    [data-testid="stDataFrame"] {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 6px;
        overflow: hidden;
    }}

    /* ── Buttons ──────────────────────────────────── */
    .stButton > button {{
        background: {COLOR_ELEVATED};
        color: {COLOR_TEXT};
        border: 1px solid {COLOR_BORDER};
        border-radius: 6px;
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        font-weight: 500;
        padding: 0.45rem 1rem;
        transition: all 0.15s ease;
    }}
    .stButton > button:hover {{
        background: {COLOR_HOVER};
        border-color: {COLOR_ACCENT};
        color: {COLOR_ACCENT};
    }}
    .stButton > button[kind="primary"] {{
        background: {COLOR_ACCENT};
        color: #0D0E10;
        border-color: {COLOR_ACCENT};
        font-weight: 600;
    }}
    .stButton > button[kind="primary"]:hover {{
        background: #E89D6A;
        border-color: #E89D6A;
    }}

    /* ── Inputs, Selects ──────────────────────────── */
    .stTextInput > div > div > input,
    .stSelectbox > div > div,
    .stMultiSelect > div > div,
    .stNumberInput > div > div > input,
    .stTextArea > div > div > textarea {{
        background-color: {COLOR_ELEVATED} !important;
        color: {COLOR_TEXT} !important;
        border: 1px solid {COLOR_BORDER_SUBTLE} !important;
        border-radius: 6px !important;
        font-family: 'Inter', sans-serif;
        font-size: 0.88rem;
    }}
    .stTextInput > div > div > input:focus,
    .stTextArea > div > div > textarea:focus {{
        border-color: {COLOR_ACCENT} !important;
        box-shadow: 0 0 0 2px rgba(216,137,85,0.15) !important;
    }}

    /* ── Tabs ─────────────────────────────────────── */
    [data-testid="stTabs"] [data-testid="stTab"] {{
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        font-weight: 500;
        color: {COLOR_TEXT_SEC};
        padding: 0.5rem 1rem;
        border-bottom: 2px solid transparent;
        transition: all 0.15s ease;
    }}
    [data-testid="stTabs"] [data-testid="stTab"][aria-selected="true"] {{
        color: {COLOR_ACCENT};
        border-bottom-color: {COLOR_ACCENT};
        font-weight: 600;
    }}
    [data-testid="stTabs"] [data-testid="stTab"]:hover {{
        color: {COLOR_TEXT};
        border-bottom-color: {COLOR_BORDER};
    }}

    /* ── Alerts / Info ───────────────────────────── */
    [data-testid="stAlert"] {{
        border-radius: 6px;
        border: 1px solid {COLOR_BORDER_SUBTLE};
        font-family: 'Inter', sans-serif;
        font-size: 0.87rem;
    }}

    /* ── Expanders ────────────────────────────────── */
    [data-testid="stExpander"] {{
        background: {COLOR_SURFACE};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 8px;
    }}
    [data-testid="stExpander"] summary {{
        font-family: 'Inter', sans-serif;
        font-weight: 500;
        font-size: 0.9rem;
        color: {COLOR_TEXT};
    }}

    /* ── Divider ──────────────────────────────────── */
    hr {{
        border-color: {COLOR_BORDER_SUBTLE};
        margin: 1rem 0;
    }}

    /* ── Code blocks ──────────────────────────────── */
    code {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        background: {COLOR_ELEVATED};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 4px;
        padding: 0.1em 0.4em;
        color: {COLOR_ACCENT};
    }}

    /* ── Toggle ───────────────────────────────────── */
    [data-testid="stToggle"] svg {{
        color: {COLOR_ACCENT};
    }}

    /* ── Spinner ──────────────────────────────────── */
    [data-testid="stSpinner"] {{
        color: {COLOR_ACCENT};
    }}

    /* ── Custom Classes ───────────────────────────── */

    /* Page header */
    .ns-page-header {{
        margin-bottom: 1.5rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid {COLOR_BORDER_SUBTLE};
    }}
    .ns-page-title {{
        font-size: 1.5rem;
        font-weight: 700;
        color: {COLOR_TEXT};
        letter-spacing: -0.02em;
        margin: 0;
    }}
    .ns-page-subtitle {{
        font-size: 0.82rem;
        color: {COLOR_TEXT_MUTED};
        margin: 0.2rem 0 0 0;
        font-family: 'Inter', sans-serif;
    }}

    /* Status badge */
    .ns-badge {{
        display: inline-flex;
        align-items: center;
        gap: 0.3em;
        padding: 0.2em 0.65em;
        font-size: 0.72rem;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        border-radius: 4px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        white-space: nowrap;
    }}
    .ns-badge-critical {{ background: rgba(224,82,82,0.12); color: {COLOR_CRITICAL}; border: 1px solid rgba(224,82,82,0.35); }}
    .ns-badge-high     {{ background: rgba(216,137,85,0.12); color: {COLOR_HIGH};     border: 1px solid rgba(216,137,85,0.35); }}
    .ns-badge-medium   {{ background: rgba(201,169,77,0.12); color: {COLOR_MEDIUM};   border: 1px solid rgba(201,169,77,0.35); }}
    .ns-badge-low      {{ background: rgba(92,143,190,0.12); color: {COLOR_LOW};      border: 1px solid rgba(92,143,190,0.35); }}
    .ns-badge-safe     {{ background: rgba(75,175,130,0.12); color: {COLOR_SAFE};     border: 1px solid rgba(75,175,130,0.35); }}
    .ns-badge-info     {{ background: rgba(100,116,139,0.12); color: {COLOR_INFO};    border: 1px solid rgba(100,116,139,0.35); }}
    .ns-badge-online   {{ background: rgba(75,175,130,0.12); color: {COLOR_SAFE};     border: 1px solid rgba(75,175,130,0.35); }}
    .ns-badge-offline  {{ background: rgba(224,82,82,0.12);  color: {COLOR_CRITICAL}; border: 1px solid rgba(224,82,82,0.35); }}
    .ns-badge-new      {{ background: rgba(92,143,190,0.12); color: {COLOR_LOW};      border: 1px solid rgba(92,143,190,0.35); }}
    .ns-badge-investigating {{ background: rgba(201,169,77,0.12); color: {COLOR_MEDIUM}; border: 1px solid rgba(201,169,77,0.35); }}
    .ns-badge-confirmed {{ background: rgba(224,82,82,0.12); color: {COLOR_CRITICAL}; border: 1px solid rgba(224,82,82,0.35); }}
    .ns-badge-closed   {{ background: rgba(100,116,139,0.12); color: {COLOR_INFO};    border: 1px solid rgba(100,116,139,0.35); }}

    /* Alert card */
    .ns-alert-card {{
        background: {COLOR_SURFACE};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 8px;
        padding: 1rem 1.25rem;
        margin-bottom: 0.6rem;
        transition: border-color 0.15s ease;
    }}
    .ns-alert-card:hover {{
        border-color: {COLOR_BORDER};
    }}
    .ns-alert-card-critical {{ border-left: 3px solid {COLOR_CRITICAL}; }}
    .ns-alert-card-high     {{ border-left: 3px solid {COLOR_HIGH}; }}
    .ns-alert-card-medium   {{ border-left: 3px solid {COLOR_MEDIUM}; }}
    .ns-alert-card-low      {{ border-left: 3px solid {COLOR_LOW}; }}

    /* Sensor status banner */
    .ns-sensor-online {{
        background: rgba(75,175,130,0.08);
        border: 1px solid rgba(75,175,130,0.3);
        border-radius: 8px;
        padding: 0.65rem 1rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1rem;
    }}
    .ns-sensor-offline {{
        background: rgba(224,82,82,0.08);
        border: 1px solid rgba(224,82,82,0.3);
        border-radius: 8px;
        padding: 0.65rem 1rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        margin-bottom: 1rem;
    }}

    /* Pulsing dot animation */
    @keyframes pulse {{
        0%, 100% {{ opacity: 1; }}
        50% {{ opacity: 0.4; }}
    }}
    .ns-pulse-dot {{
        width: 8px; height: 8px;
        border-radius: 50%;
        background: {COLOR_SAFE};
        animation: pulse 1.5s ease-in-out infinite;
        display: inline-block;
    }}
    .ns-pulse-dot-red {{
        width: 8px; height: 8px;
        border-radius: 50%;
        background: {COLOR_CRITICAL};
        display: inline-block;
    }}

    /* Stat card */
    .ns-stat-card {{
        background: {COLOR_SURFACE};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 8px;
        padding: 1.2rem;
        text-align: center;
    }}
    .ns-stat-value {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 2rem;
        font-weight: 600;
        color: {COLOR_TEXT};
        line-height: 1;
    }}
    .ns-stat-label {{
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: {COLOR_TEXT_MUTED};
        margin-top: 0.4rem;
        font-weight: 500;
    }}

    /* Info/data row  */
    .ns-data-row {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem 0;
        border-bottom: 1px solid {COLOR_BORDER_SUBTLE};
        font-size: 0.87rem;
    }}
    .ns-data-row:last-child {{ border-bottom: none; }}
    .ns-data-label {{ color: {COLOR_TEXT_MUTED}; font-weight: 500; }}
    .ns-data-value {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        color: {COLOR_TEXT};
    }}

    /* Section heading */
    .ns-section-heading {{
        font-size: 0.72rem;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: {COLOR_TEXT_MUTED};
        font-weight: 600;
        margin: 1.25rem 0 0.75rem 0;
        padding-bottom: 0.4rem;
        border-bottom: 1px solid {COLOR_BORDER_SUBTLE};
    }}

    /* Sidebar group heading */
    .ns-nav-group {{
        font-size: 0.65rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        color: {COLOR_TEXT_MUTED};
        font-weight: 600;
        margin: 1rem 0 0.4rem 0.5rem;
    }}

    /* Login page full-screen */
    .ns-login-container {{
        max-width: 400px;
        margin: 4rem auto;
        background: {COLOR_SURFACE};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 12px;
        padding: 2.5rem 2rem;
    }}
    .ns-login-logo {{
        text-align: center;
        margin-bottom: 2rem;
    }}
    .ns-login-logo-icon {{
        font-size: 3rem;
        line-height: 1;
        margin-bottom: 0.5rem;
    }}
    .ns-login-logo-title {{
        font-size: 1.5rem;
        font-weight: 800;
        color: {COLOR_TEXT};
        letter-spacing: -0.02em;
    }}
    .ns-login-logo-sub {{
        font-size: 0.78rem;
        color: {COLOR_TEXT_MUTED};
        letter-spacing: 0.06em;
        text-transform: uppercase;
        font-weight: 500;
    }}

    /* MITRE tag */
    .ns-mitre-tag {{
        display: inline-block;
        background: rgba(92,143,190,0.1);
        border: 1px solid rgba(92,143,190,0.3);
        border-radius: 4px;
        padding: 0.15em 0.5em;
        font-size: 0.72rem;
        font-family: 'JetBrains Mono', monospace;
        color: {COLOR_LOW};
        margin-right: 0.4em;
    }}

    /* Timeline event */
    .ns-timeline-item {{
        display: flex;
        gap: 0.75rem;
        align-items: flex-start;
        padding: 0.6rem 0;
        border-bottom: 1px solid {COLOR_BORDER_SUBTLE};
        font-size: 0.84rem;
    }}
    .ns-timeline-dot {{
        width: 8px; height: 8px;
        border-radius: 50%;
        background: {COLOR_ACCENT};
        margin-top: 0.35rem;
        flex-shrink: 0;
    }}
    .ns-timeline-time {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        color: {COLOR_TEXT_MUTED};
        min-width: 140px;
        flex-shrink: 0;
    }}
    .ns-timeline-content {{ color: {COLOR_TEXT_SEC}; }}

    /* Note card */
    .ns-note-card {{
        background: {COLOR_ELEVATED};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 6px;
        padding: 0.75rem 1rem;
        margin-bottom: 0.5rem;
        font-size: 0.84rem;
    }}
    .ns-note-meta {{
        font-size: 0.72rem;
        color: {COLOR_TEXT_MUTED};
        font-family: 'JetBrains Mono', monospace;
        margin-bottom: 0.25rem;
    }}

    /* Progress bar */
    .ns-progress-bar {{
        background: {COLOR_ELEVATED};
        border-radius: 4px;
        height: 6px;
        overflow: hidden;
        margin: 0.3rem 0;
    }}
    .ns-progress-fill {{
        height: 100%;
        border-radius: 4px;
        background: linear-gradient(90deg, {COLOR_ACCENT}, #E89D6A);
        transition: width 0.3s ease;
    }}

    /* Hide Streamlit default elements */
    #MainMenu {{ visibility: hidden; }}
    footer {{ visibility: hidden; }}
    [data-testid="stDecoration"] {{ display: none; }}

</style>
"""


def get_plotly_dark_template() -> go.layout.Template:
    """Creates custom Plotly template matching NetSentry SOC palette."""
    t = pio.templates["plotly_dark"].to_plotly_json()
    template = go.layout.Template(t)
    template.layout.paper_bgcolor = COLOR_BG
    template.layout.plot_bgcolor  = COLOR_SURFACE
    template.layout.font.family   = "Inter, sans-serif"
    template.layout.font.color    = COLOR_TEXT
    template.layout.font.size     = 12
    template.layout.xaxis.gridcolor   = COLOR_BORDER_SUBTLE
    template.layout.yaxis.gridcolor   = COLOR_BORDER_SUBTLE
    template.layout.xaxis.linecolor   = COLOR_BORDER
    template.layout.yaxis.linecolor   = COLOR_BORDER
    template.layout.colorway = [
        COLOR_ACCENT, COLOR_LOW, COLOR_SAFE, COLOR_MEDIUM,
        COLOR_HIGH, COLOR_CRITICAL, "#8B5CF6", "#06B6D4"
    ]
    return template


def apply_soc_theme():
    """Applies global NetSentry CSS and Plotly dark template."""
    st.markdown(NETSENTRY_CSS, unsafe_allow_html=True)
    try:
        pio.templates["netsentry"] = get_plotly_dark_template()
        pio.templates.default = "netsentry"
    except Exception:
        pio.templates.default = "plotly_dark"


def render_severity_badge(severity: str) -> str:
    """Renders HTML severity badge."""
    sev = severity.upper()
    cls_map = {
        "CRITICAL": "ns-badge-critical",
        "HIGH":     "ns-badge-high",
        "MEDIUM":   "ns-badge-medium",
        "LOW":      "ns-badge-low",
        "INFO":     "ns-badge-info",
        "SAFE":     "ns-badge-safe",
    }
    dot_map = {
        "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵",
        "INFO": "⚪", "SAFE": "🟢",
    }
    css_cls = cls_map.get(sev, "ns-badge-info")
    dot     = dot_map.get(sev, "⚪")
    return f'<span class="ns-badge {css_cls}">{dot} {sev}</span>'


def render_status_badge(status: str) -> str:
    """Renders HTML status badge for alert/case status."""
    s = status.upper()
    cls_map = {
        "NEW":           "ns-badge-new",
        "INVESTIGATING": "ns-badge-investigating",
        "CONFIRMED":     "ns-badge-confirmed",
        "FALSE_POSITIVE":"ns-badge-info",
        "CLOSED":        "ns-badge-closed",
        "OPEN":          "ns-badge-new",
        "RESOLVED":      "ns-badge-safe",
        "ONLINE":        "ns-badge-online",
        "OFFLINE":       "ns-badge-offline",
    }
    css_cls = cls_map.get(s, "ns-badge-info")
    label = s.replace("_", " ")
    return f'<span class="ns-badge {css_cls}">{label}</span>'


def render_page_header(title: str, subtitle: str = "", icon: str = ""):
    """Renders a consistent page header."""
    icon_html = f'<span style="font-size:1.4rem;margin-right:0.5rem;">{icon}</span>' if icon else ""
    st.markdown(f"""
    <div class="ns-page-header">
        <div class="ns-page-title">{icon_html}{title}</div>
        {"<div class='ns-page-subtitle'>" + subtitle + "</div>" if subtitle else ""}
    </div>
    """, unsafe_allow_html=True)


def render_sensor_banner(is_online: bool, sensor_name: str = "Local Sensor", details: str = ""):
    """Renders the sensor status banner at top of page."""
    if is_online:
        dot_html = '<span class="ns-pulse-dot"></span>'
        css_cls  = "ns-sensor-online"
        status_text = f"<strong style='color:#4BAF82'>SENSOR ONLINE</strong> — {sensor_name}"
    else:
        dot_html = '<span class="ns-pulse-dot-red"></span>'
        css_cls  = "ns-sensor-offline"
        status_text = f"<strong style='color:#E05252'>SENSOR OFFLINE</strong> — No active capture running"
    detail_html = f"<span style='font-size:0.78rem;color:#798690;margin-left:0.5rem;'>{details}</span>" if details else ""
    st.markdown(f"""
    <div class="{css_cls}">
        {dot_html}
        <span style='font-size:0.85rem;font-family:Inter,sans-serif;'>{status_text}</span>
        {detail_html}
    </div>
    """, unsafe_allow_html=True)


def render_metric_card(label: str, value: str, delta: str = "", color: str = COLOR_ACCENT):
    """Renders a premium metric card via HTML."""
    delta_html = ""
    if delta:
        delta_color = COLOR_SAFE if not delta.startswith("-") else COLOR_CRITICAL
        delta_html = f'<div style="font-size:0.75rem;color:{delta_color};margin-top:0.2rem;font-family:JetBrains Mono,monospace;">{delta}</div>'
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                border-left:3px solid {color};border-radius:8px;
                padding:1rem 1.25rem;margin-bottom:0.25rem;">
        <div style="font-size:0.7rem;text-transform:uppercase;letter-spacing:0.08em;
                    color:{COLOR_TEXT_MUTED};font-weight:600;margin-bottom:0.4rem;">{label}</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;
                    font-weight:600;color:{COLOR_TEXT};line-height:1;">{value}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def section_heading(text: str):
    """Renders a small section heading."""
    st.markdown(f'<div class="ns-section-heading">{text}</div>', unsafe_allow_html=True)
