import streamlit as st
import plotly.io as pio
import plotly.graph_objects as go

# Stitch Design Tokens
COLOR_CANVAS = "#0b0f17"
COLOR_SURFACE = "#111827"
COLOR_RAISED = "#162032"
COLOR_DRAWER = "#1f293d"
COLOR_BORDER_SUBTLE = "#1f2937"
COLOR_BORDER_STRONG = "#283548"

COLOR_TEXT_PRIMARY = "#f3f4f6"
COLOR_TEXT_SECONDARY = "#9ca3af"
COLOR_TEXT_MUTED = "#6b7280"

COLOR_CRITICAL = "#ef4444"
COLOR_HIGH = "#f97316"
COLOR_MEDIUM = "#eab308"
COLOR_LOW = "#3b82f6"
COLOR_SAFE = "#10b981"

SEVERITY_COLORS = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH": COLOR_HIGH,
    "MEDIUM": COLOR_MEDIUM,
    "LOW": COLOR_LOW,
    "INFO": "#64748b"
}

SOC_CSS = f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] {{
        font-family: 'Inter', sans-serif;
        background-color: {COLOR_CANVAS};
        color: {COLOR_TEXT_PRIMARY};
    }}

    .stApp {{
        background-color: {COLOR_CANVAS};
    }}

    /* Sidebar Styling */
    [data-testid="stSidebar"] {{
        background-color: {COLOR_SURFACE};
        border-right: 1px solid {COLOR_BORDER_SUBTLE};
    }}

    /* Card Containers */
    div[data-testid="stVerticalBlock"] > div[style*="background-color"] {{
        background-color: {COLOR_SURFACE};
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 6px;
        padding: 1rem;
    }}

    /* Metrics Styling */
    div[data-testid="stMetricValue"] {{
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        font-size: 1.8rem;
        color: {COLOR_TEXT_PRIMARY};
    }}

    div[data-testid="stMetricLabel"] {{
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        color: {COLOR_TEXT_SECONDARY};
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }}

    /* Dataframes and Tables */
    div[data-testid="stDataFrame"] {{
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        border: 1px solid {COLOR_BORDER_SUBTLE};
        border-radius: 4px;
    }}

    /* Badges */
    .badge {{
        display: inline-block;
        padding: 0.2em 0.6em;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        border-radius: 4px;
        text-transform: uppercase;
    }}
    .badge-critical {{ background-color: rgba(239, 68, 68, 0.15); color: {COLOR_CRITICAL}; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-high {{ background-color: rgba(249, 115, 22, 0.15); color: {COLOR_HIGH}; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .badge-medium {{ background-color: rgba(234, 179, 8, 0.15); color: {COLOR_MEDIUM}; border: 1px solid rgba(234, 179, 8, 0.4); }}
    .badge-low {{ background-color: rgba(59, 130, 246, 0.15); color: {COLOR_LOW}; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-safe {{ background-color: rgba(16, 185, 129, 0.15); color: {COLOR_SAFE}; border: 1px solid rgba(16, 185, 129, 0.4); }}

    /* Headings */
    h1, h2, h3, h4 {{
        font-family: 'Inter', sans-serif;
        color: {COLOR_TEXT_PRIMARY};
        font-weight: 600;
    }}
</style>
"""

def get_plotly_dark_template() -> go.layout.Template:
    """Creates custom Plotly template matching Stitch SOC palette."""
    t = pio.templates["plotly_dark"]
    t.layout.paper_bgcolor = COLOR_CANVAS
    t.layout.plot_bgcolor = COLOR_SURFACE
    t.layout.font.family = "Inter, sans-serif"
    t.layout.font.color = COLOR_TEXT_PRIMARY
    t.layout.xaxis.gridcolor = COLOR_BORDER_SUBTLE
    t.layout.yaxis.gridcolor = COLOR_BORDER_SUBTLE
    t.layout.colorway = [COLOR_LOW, COLOR_SAFE, COLOR_MEDIUM, COLOR_HIGH, COLOR_CRITICAL, "#8b5cf6"]
    return t

def apply_soc_theme():
    """Applies global custom CSS and Plotly dark template."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)
    pio.templates["netwatch_dark"] = get_plotly_dark_template()
    pio.templates.default = "netwatch_dark"

def render_severity_badge(severity: str) -> str:
    """Renders HTML badge for severity level."""
    sev = severity.upper()
    cls_map = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low"
    }
    css_cls = cls_map.get(sev, "badge-low")
    return f'<span class="badge {css_cls}">{sev}</span>'
