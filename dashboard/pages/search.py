"""
Global Search — NetSentry SOC
Cross-entity full-text search across alerts, network events, DNS events,
cases, and investigations. Results are grouped by entity type and
support one-click pivot to the relevant detail page.
"""
import streamlit as st
import pandas as pd
from dashboard.theme import (
    COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_SEC, COLOR_TEXT_MUTED,
    COLOR_SURFACE, COLOR_ELEVATED, COLOR_BORDER_SUBTLE, COLOR_SAFE,
    COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW,
    render_page_header, render_severity_badge, render_status_badge, section_heading
)

render_page_header(
    "Global Search",
    "Search across alerts, network events, DNS queries, and cases",
    "🔎"
)

# ─── Search bar ───────────────────────────────────────────────────────────────
s_col, b_col = st.columns([5, 1])
with s_col:
    query = st.text_input(
        "Search",
        placeholder="IP address, domain, alert type, case title, reason…",
        label_visibility="collapsed",
        key="global_search_query",
    )
with b_col:
    search_btn = st.button("🔎  Search", type="primary", use_container_width=True)

# Filters row
fc1, fc2, fc3 = st.columns(3)
with fc1:
    search_in = st.multiselect(
        "Search in",
        ["Alerts", "Network Events", "DNS Events", "Cases"],
        default=["Alerts", "Network Events", "DNS Events", "Cases"],
        label_visibility="collapsed",
    )
with fc2:
    result_limit = st.selectbox(
        "Max results per type",
        [25, 50, 100],
        index=0,
        label_visibility="collapsed",
    )
with fc3:
    sev_filter = st.selectbox(
        "Severity",
        ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        label_visibility="collapsed",
    )

if not query or len(query.strip()) < 2:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:3rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:2rem 0;">
        <div style="font-size:1.5rem;margin-bottom:0.5rem;">🔎</div>
        <div style="font-weight:500;margin-bottom:0.25rem;">Enter at least 2 characters to search</div>
        <div style="font-size:0.8rem;">
            Searches IP addresses, domains, alert types, reasons, case titles, and analyst notes.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

q = query.strip()

# ─── Run searches ─────────────────────────────────────────────────────────────
with st.spinner(f"Searching for '{q}'…"):
    results: dict[str, pd.DataFrame] = {}
    total_hits = 0

    # ── Alerts ────────────────────────────────────────────────────────────────
    if "Alerts" in search_in:
        from src.database.repositories import get_alerts
        try:
            alerts_df = get_alerts(
                source_ip=q if _looks_like_ip(q) else None,
                limit=result_limit * 4,
            )
            if alerts_df.empty:
                # Fallback: fetch more and filter in-memory
                alerts_df = get_alerts(limit=2000)

            if not alerts_df.empty:
                mask = (
                    alerts_df["source_ip"].str.contains(q, case=False, na=False) |
                    alerts_df["destination_ip"].str.contains(q, case=False, na=False) |
                    alerts_df["alert_type"].str.contains(q, case=False, na=False) |
                    alerts_df["reason"].str.contains(q, case=False, na=False) |
                    alerts_df["alert_id"].str.contains(q, case=False, na=False)
                )
                if sev_filter != "All":
                    mask &= alerts_df["severity"].str.upper() == sev_filter
                matched = alerts_df[mask].head(result_limit)
                if not matched.empty:
                    results["Alerts"] = matched
                    total_hits += len(matched)
        except Exception:
            pass

    # ── Network Events ─────────────────────────────────────────────────────────
    if "Network Events" in search_in:
        from src.database.repositories import get_network_events
        try:
            if _looks_like_ip(q):
                ne_src = get_network_events(source_ip=q, limit=result_limit)
                ne_dst = get_network_events(destination_ip=q, limit=result_limit)
                ne_df  = pd.concat([ne_src, ne_dst]).drop_duplicates(subset=["event_id"]).head(result_limit)
            else:
                ne_df = get_network_events(domain=q, limit=result_limit)
                if ne_df.empty:
                    ne_df = get_network_events(limit=2000)
                    ne_df = ne_df[
                        ne_df.apply(lambda r: q.lower() in str(r).lower(), axis=1)
                    ].head(result_limit)

            if not ne_df.empty:
                results["Network Events"] = ne_df
                total_hits += len(ne_df)
        except Exception:
            pass

    # ── DNS Events ─────────────────────────────────────────────────────────────
    if "DNS Events" in search_in:
        from src.database.repositories import get_dns_events
        try:
            dns_df = get_dns_events(
                source_ip=q if _looks_like_ip(q) else None,
                domain=None if _looks_like_ip(q) else q,
                limit=result_limit,
            )
            if not dns_df.empty:
                results["DNS Events"] = dns_df
                total_hits += len(dns_df)
        except Exception:
            pass

    # ── Cases ──────────────────────────────────────────────────────────────────
    if "Cases" in search_in:
        try:
            from src.database.database import get_db_connection
            import pandas as _pd
            conn = get_db_connection()
            try:
                cases_df = _pd.read_sql_query(
                    "SELECT * FROM cases ORDER BY created_at DESC", conn
                )
                conn.close()
            except Exception:
                conn.close()
                cases_df = _pd.DataFrame()

            if not cases_df.empty:
                mask = (
                    cases_df["title"].str.contains(q, case=False, na=False) |
                    cases_df["description"].str.contains(q, case=False, na=False) |
                    cases_df["case_id"].str.contains(q, case=False, na=False) |
                    cases_df["created_by"].str.contains(q, case=False, na=False)
                )
                matched_cases = cases_df[mask].head(result_limit)
                if not matched_cases.empty:
                    results["Cases"] = matched_cases
                    total_hits += len(matched_cases)
        except Exception:
            pass


def _looks_like_ip(s: str) -> bool:
    """Crude check — contains dots and digits suggesting an IP."""
    parts = s.split(".")
    return len(parts) >= 2 and all(p.isdigit() for p in parts if p)


# ─── Results summary ──────────────────────────────────────────────────────────
if total_hits == 0:
    st.markdown(f"""
    <div style="background:{COLOR_SURFACE};border:1px dashed {COLOR_BORDER_SUBTLE};
                border-radius:8px;padding:2.5rem;text-align:center;color:{COLOR_TEXT_MUTED};margin:1rem 0;">
        <div style="font-size:1.2rem;margin-bottom:0.3rem;">🔍</div>
        <div>No results found for <code>{q}</code></div>
        <div style="font-size:0.78rem;margin-top:0.25rem;">
            Try a shorter term, IP address, domain name, or alert type.
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

st.markdown(f"""
<div style="font-size:0.85rem;color:{COLOR_TEXT_MUTED};margin-bottom:1rem;">
    Found <strong style="color:{COLOR_ACCENT};">{total_hits}</strong> result{'s' if total_hits != 1 else ''}
    for <code>{q}</code> across {len(results)} categor{'ies' if len(results) != 1 else 'y'}
</div>
""", unsafe_allow_html=True)

# ─── Render results by entity type ────────────────────────────────────────────

# ── ALERTS ────────────────────────────────────────────────────────────────────
if "Alerts" in results:
    alerts_res = results["Alerts"]
    section_heading(f"🚨 Alerts ({len(alerts_res)})")
    for _, row in alerts_res.iterrows():
        sev = row.get("severity", "LOW").upper()
        sev_colors = {
            "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
        }
        lb = sev_colors.get(sev, COLOR_LOW)
        reason_txt = str(row.get("reason", ""))
        # Highlight the query term in reason
        hl_reason = reason_txt.replace(
            q, f'<mark style="background:rgba(216,137,85,0.3);border-radius:2px;">{q}</mark>'
        ) if q and len(q) > 1 else reason_txt

        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-left:3px solid {lb};border-radius:8px;
                    padding:0.8rem 1.25rem;margin-bottom:0.3rem;">
            <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.3rem;flex-wrap:wrap;">
                {render_severity_badge(sev)}
                {render_status_badge(row.get('status','NEW'))}
                <code style="font-size:0.8rem;color:{COLOR_TEXT};">{row['alert_type']}</code>
                <span style="font-size:0.75rem;color:{COLOR_TEXT_MUTED};">
                    Score: <strong style="color:{COLOR_ACCENT};">{row['risk_score']}</strong>
                </span>
                <span style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};margin-left:auto;">
                    {str(row.get('last_seen',''))[:16]}
                </span>
            </div>
            <div style="font-size:0.8rem;color:{COLOR_TEXT_SEC};">
                <code>{row['source_ip']}</code>
                <span style="color:{COLOR_TEXT_MUTED};margin:0 0.4rem;">→</span>
                <code>{row['destination_ip']}:{row.get('destination_port','?')}</code>
                <span style="color:{COLOR_TEXT_MUTED};margin-left:0.5rem;font-size:0.78rem;">
                    {hl_reason[:120]}{'…' if len(hl_reason) > 120 else ''}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        a1, a2, a3 = st.columns([1.5, 1.5, 6])
        with a1:
            if st.button("🔬 Investigate", key=f"gs_inv_{row['alert_id']}", use_container_width=True):
                st.session_state["selected_alert_id"] = row["alert_id"]
                st.session_state["current_page"]      = "Investigation"
                st.rerun()
        with a2:
            if st.button("🎯 IP Intel", key=f"gs_ip_{row['alert_id']}", use_container_width=True):
                st.session_state["investigate_ip"] = row["source_ip"]
                st.session_state["current_page"]   = "IP Investigation"
                st.rerun()
        st.markdown("<div style='height:0.2rem;'></div>", unsafe_allow_html=True)

    st.divider()

# ── NETWORK EVENTS ────────────────────────────────────────────────────────────
if "Network Events" in results:
    ne_res = results["Network Events"]
    section_heading(f"🌐 Network Events ({len(ne_res)})")
    show_cols = [c for c in ["timestamp", "source_ip", "destination_ip",
                              "destination_port", "protocol", "bytes_sent", "log_source"]
                 if c in ne_res.columns]
    st.dataframe(ne_res[show_cols].sort_values("timestamp", ascending=False),
                 use_container_width=True, hide_index=True, height=280)

    # Quick pivot to IP investigation from top source IP
    if "source_ip" in ne_res.columns:
        top_ip = ne_res["source_ip"].value_counts().index[0]
        if st.button(f"🎯  Investigate top IP: {top_ip}", key="gs_ne_pivot"):
            st.session_state["investigate_ip"] = top_ip
            st.session_state["current_page"]   = "IP Investigation"
            st.rerun()

    st.divider()

# ── DNS EVENTS ────────────────────────────────────────────────────────────────
if "DNS Events" in results:
    dns_res = results["DNS Events"]
    section_heading(f"🔍 DNS Events ({len(dns_res)})")
    st.dataframe(
        dns_res.sort_values("timestamp", ascending=False),
        use_container_width=True, hide_index=True, height=260
    )
    st.divider()

# ── CASES ─────────────────────────────────────────────────────────────────────
if "Cases" in results:
    cases_res = results["Cases"]
    section_heading(f"📁 Cases ({len(cases_res)})")
    for _, row in cases_res.iterrows():
        sev = row.get("severity", "MEDIUM").upper()
        sev_colors = {
            "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
            "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_LOW
        }
        lb = sev_colors.get(sev, COLOR_MEDIUM)
        title_hl = str(row["title"]).replace(
            q, f'<mark style="background:rgba(216,137,85,0.3);border-radius:2px;">{q}</mark>'
        ) if q else str(row["title"])

        st.markdown(f"""
        <div style="background:{COLOR_SURFACE};border:1px solid {COLOR_BORDER_SUBTLE};
                    border-left:3px solid {lb};border-radius:8px;
                    padding:0.8rem 1.25rem;margin-bottom:0.3rem;">
            <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem;">
                <div>
                    <div style="font-weight:600;color:{COLOR_TEXT};margin-bottom:0.2rem;">{title_hl}</div>
                    <div style="display:flex;align-items:center;gap:0.5rem;">
                        {render_status_badge(row.get('status','OPEN'))}
                        <span style="font-size:0.72rem;color:{lb};font-weight:600;">{sev}</span>
                        <span style="font-size:0.72rem;color:{COLOR_TEXT_MUTED};">
                            by {row.get('created_by','?')} · {str(row.get('created_at',''))[:10]}
                        </span>
                    </div>
                    {f'<div style="font-size:0.78rem;color:{COLOR_TEXT_MUTED};margin-top:0.2rem;">{str(row.get("description",""))[:100]}…</div>' if row.get('description') else ''}
                </div>
                <code style="font-size:0.7rem;color:{COLOR_TEXT_MUTED};">{row['case_id'][:8]}…</code>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if st.button("📁  Open Case", key=f"gs_case_{row['case_id']}", use_container_width=False):
            st.session_state["selected_case_id"] = row["case_id"]
            st.session_state["current_page"]     = "Cases"
            st.rerun()

        st.markdown("<div style='height:0.2rem;'></div>", unsafe_allow_html=True)

