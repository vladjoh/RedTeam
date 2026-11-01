"""M365 Red Team — External Entra domain scan (Windows-local)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from app.ai.analyzer import AttackPathAnalyzer
from app.core.config import load_settings
from app.core.models import Likelihood, Severity
from app.modules.engine import AssessmentEngine
from app.reports.generator import ReportGenerator

st.set_page_config(
    page_title="M365 Red Team — External scan",
    page_icon="RT",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEV_COLORS = {
    "high": "#b42318",
    "medium": "#b54708",
    "low": "#175cd3",
    "info": "#475467",
    "pass": "#027a48",
}


def inject_css() -> None:
    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Sora:wght@600;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
          .block-container { padding-top: 1.1rem; max-width: 1080px; }
          h1,h2,h3 { font-family: Sora, sans-serif !important; letter-spacing: -0.02em; }
          .brand { font-family: Sora, sans-serif; font-weight: 700; font-size: 1.9rem; color: #0b3d36; margin: 0; }
          .sub { color: #5b6b7c; margin: 0.25rem 0 0.85rem; }
          .sev-high { background:#fef3f2; border:1px solid #fecdca; color:#b42318; padding:0.85rem 1rem; }
          .sev-medium { background:#fffaeb; border:1px solid #fedf89; color:#b54708; padding:0.85rem 1rem; }
          .sev-low { background:#eff8ff; border:1px solid #b2ddff; color:#175cd3; padding:0.85rem 1rem; }
          .card { border:1px solid #d7dee7; border-left-width:5px; background:#fff; padding:0.8rem 0.95rem; margin-bottom:0.55rem; }
          .pill { display:inline-block; font-size:0.72rem; font-weight:700; letter-spacing:0.04em; text-transform:uppercase; }
          .notice { border-left:3px solid #c45f1a; background:rgba(196,95,26,.08); padding:0.75rem 0.9rem; margin:0.75rem 0 1rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    inject_css()
    settings = load_settings()

    st.markdown('<p class="brand">M365 Red Team</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub">External Entra / Microsoft 365 domain scan — no login. '
        "Shows High / Medium / Low findings and the most likely bypass paths.</p>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="notice"><strong>Authorized use only.</strong> '
        "Tell the tenant owner before you scan. Attackers can query the same public signals. "
        "Verify every finding on the target before you change controls.</div>",
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("External scan")
        domain = st.text_input(
            "Target domain",
            value=settings.tenant.domain,
            placeholder="contoso.com",
            help="Public domain or tenant.onmicrosoft.com you are authorized to test.",
        )
        st.caption("Usually finishes in a few seconds.")
        start = st.button("Start external scan", type="primary", use_container_width=True)

    if start:
        if not domain.strip():
            st.error("Enter an authorized domain.")
            return
        settings.tenant.domain = domain.strip()
        with st.spinner(f"Scanning public Entra / M365 signals for {settings.tenant.domain}…"):
            result = AssessmentEngine(settings).run(settings.tenant.domain)
            result.ai_summary = AttackPathAnalyzer(settings).summarize(result)
            paths = ReportGenerator(settings).write(result)
            st.session_state.last_result = result
            st.session_state.last_paths = paths

    result = st.session_state.get("last_result")
    if not result:
        st.info("Enter a domain and click **Start external scan**.")
        st.markdown(
            """
            ### What you get
            - **HIGH / MEDIUM / LOW** severity counts  
            - **Most likely bypass** path with why it wins  
            - **Possible** and **less likely** paths for prioritization  
            - Downloadable HTML report with evidence  
            """
        )
        return

    briefing = result.metadata.get("likelihood_briefing") or {}
    counts = briefing.get("counts") or result.high_medium_low_counts()

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f'<div class="sev-high"><div class="pill">High</div><div style="font-size:2rem;font-weight:700">{counts.get("high", 0)}</div>'
            f"<div>Fix first — likely attacker shortcuts</div></div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="sev-medium"><div class="pill">Medium</div><div style="font-size:2rem;font-weight:700">{counts.get("medium", 0)}</div>'
            f"<div>Real risk — plan remediation</div></div>",
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<div class="sev-low"><div class="pill">Low</div><div style="font-size:2rem;font-weight:700">{counts.get("low", 0)}</div>'
            f"<div>Weaker signal / smaller blast radius</div></div>",
            unsafe_allow_html=True,
        )

    st.caption(briefing.get("headline", ""))

    most = briefing.get("most_likely_bypass") or {}
    st.subheader("Most likely bypass")
    st.markdown(f"**{most.get('summary', 'See High findings')}**")
    if most.get("why"):
        st.write(most["why"])
    for i, step in enumerate(most.get("steps") or [], 1):
        st.markdown(f"{i}. {step}")

    if most.get("items"):
        with st.expander("Supporting High/Medium findings", expanded=True):
            for item in most["items"]:
                color = SEV_COLORS.get(item["severity"], "#475467")
                st.markdown(
                    f'<div class="card" style="border-left-color:{color}">'
                    f'<span class="pill" style="color:{color}">{item["severity"]}</span> '
                    f"<strong>{item['title']}</strong><br/>{item['why']}</div>",
                    unsafe_allow_html=True,
                )

    st.subheader("Possible paths")
    st.caption("Real issues, but usually not the shortest bypass from this vantage point.")
    possible_items = (briefing.get("possible") or {}).get("items") or []
    if not possible_items:
        st.write("No medium-priority possible paths in this run.")
    for item in possible_items:
        color = SEV_COLORS.get(item["severity"], "#475467")
        st.markdown(
            f'<div class="card" style="border-left-color:{color}">'
            f'<span class="pill" style="color:{color}">{item["severity"]}</span> '
            f"<strong>{item['title']}</strong><br/>{item['why']}</div>",
            unsafe_allow_html=True,
        )

    less = briefing.get("less_likely") or {}
    st.subheader("Less likely / informational")
    st.caption(less.get("summary", "Lower priority — still verify, but do not treat as urgent."))
    less_items = less.get("items") or []
    if not less_items:
        st.write("No less-likely items listed.")
    for item in less_items:
        color = SEV_COLORS.get(item["severity"], "#475467")
        st.markdown(
            f'<div class="card" style="border-left-color:{color}">'
            f'<span class="pill" style="color:{color}">{item["severity"]}</span> '
            f"<strong>{item['title']}</strong><br/>{item['why']}</div>",
            unsafe_allow_html=True,
        )

    st.subheader("Executive narrative")
    st.write(result.ai_summary)

    st.subheader("All findings")
    # Group by severity High → Medium → Low → other
    order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.PASS, Severity.INFO]
    for sev in order:
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        st.markdown(f"#### {sev.label}")
        for f in group:
            color = SEV_COLORS.get(f.severity.value, "#475467")
            like = f.likelihood.label if isinstance(f.likelihood, Likelihood) else f.likelihood
            with st.expander(f"[{f.severity.value.upper()}] {f.title}", expanded=False):
                st.write(f.description)
                if f.why:
                    st.markdown(f"**Why it matters:** {f.why}")
                st.markdown(f"**Likelihood:** {like}")
                if f.attack_path:
                    st.markdown(f"**Attack path:** {f.attack_path}")
                if f.barrier:
                    st.markdown(f"**Barrier:** {f.barrier}")
                if f.remediation:
                    st.markdown(f"**Remediation:** {f.remediation}")
                if f.evidence:
                    st.json(f.evidence)

    paths = st.session_state.get("last_paths") or {}
    if paths.get("html"):
        path = Path(paths["html"])
        st.download_button(
            "Download HTML report",
            data=path.read_text(encoding="utf-8"),
            file_name=path.name,
            mime="text/html",
        )


if __name__ == "__main__":
    main()