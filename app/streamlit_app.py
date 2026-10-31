"""M365 Red Team Assessment — Streamlit dashboard (Windows-local)."""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `streamlit run app/streamlit_app.py` from repo root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st

from app.ai.analyzer import AttackPathAnalyzer
from app.auth.msal_auth import AuthStatus, GraphAuthSession
from app.core.config import load_settings
from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.engine import AssessmentEngine
from app.reports.generator import ReportGenerator

st.set_page_config(
    page_title="M365 Red Team",
    page_icon="RT",
    layout="wide",
    initial_sidebar_state="expanded",
)

SEVERITY_COLORS = {
    Severity.CRITICAL: "#b42318",
    Severity.HIGH: "#c4320a",
    Severity.MEDIUM: "#b54708",
    Severity.LOW: "#175cd3",
    Severity.INFO: "#475467",
    Severity.PASS: "#027a48",
}


def inject_css() -> None:
    st.markdown(
        """
        <style>
          @import url('https://fonts.googleapis.com/css2?family=Sora:wght@500;650;700&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
          html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
          .block-container { padding-top: 1.25rem; max-width: 1100px; }
          h1, h2, h3 { font-family: 'Sora', sans-serif !important; letter-spacing: -0.02em; }
          .hero-brand {
            font-family: 'Sora', sans-serif;
            font-weight: 700;
            font-size: 2rem;
            margin: 0;
            color: #0b3d36;
          }
          .hero-sub { color: #5b6b7c; margin: 0.25rem 0 1rem; }
          .status-pill {
            display: inline-block;
            padding: 0.2rem 0.55rem;
            border: 1px solid #c9d4de;
            background: #eef6f4;
            color: #0b3d36;
            font-size: 0.8rem;
            margin-bottom: 0.75rem;
          }
          .finding-card {
            border: 1px solid #d7dee7;
            border-left-width: 4px;
            padding: 0.75rem 0.9rem;
            margin-bottom: 0.55rem;
            background: #fff;
          }
          div[data-testid="stSidebar"] { background: linear-gradient(180deg, #f3f7f6 0%, #e7efed 100%); }
        </style>
        """,
        unsafe_allow_html=True,
    )


def main() -> None:
    inject_css()
    settings = load_settings()

    st.markdown('<p class="hero-brand">M365 Red Team</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="hero-sub">Authorized Microsoft 365 attack-path assessment — '
        "how far an attacker can get, and which barriers stop them.</p>",
        unsafe_allow_html=True,
    )

    mode_label = "Demo mode — no live tenant connected" if settings.assessment.demo_mode else "Live assessment mode"
    st.markdown(f'<span class="status-pill">{mode_label}</span>', unsafe_allow_html=True)

    with st.sidebar:
        st.header("Execution")
        st.caption("Manual run on this Windows workstation.")
        tenant = st.text_input(
            "TARGET TENANT",
            value=settings.tenant.domain,
            help="Example tenant domain — not necessarily connected.",
        )
        settings.tenant.domain = tenant.strip() or settings.tenant.domain

        profile_key = st.radio(
            "Attack profile",
            options=[p.value for p in AttackProfile],
            format_func=lambda v: AttackProfile(v).label,
            index=[p.value for p in AttackProfile].index(settings.assessment.default_profile)
            if settings.assessment.default_profile in {p.value for p in AttackProfile}
            else 0,
        )
        profile = AttackProfile(profile_key)
        st.info(profile.description)

        st.subheader("Test categories")
        selected: list[AssessmentCategory] = []
        for cat in AssessmentCategory:
            default_on = cat.value in settings.assessment.categories or not settings.assessment.categories
            if st.checkbox(cat.label, value=default_on, key=f"cat_{cat.value}"):
                selected.append(cat)

        demo = st.toggle("Demo mode", value=settings.assessment.demo_mode)
        settings.assessment.demo_mode = demo

        authenticate = st.button(
            "Authenticate (MSAL)",
            disabled=demo or profile == AttackProfile.EXTERNAL,
            use_container_width=True,
        )
        start = st.button("Start Red Team Assessment", type="primary", use_container_width=True)

    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Profile", profile.label)
    col_b.metric("Categories", len(selected))
    col_c.metric("Tenant", settings.tenant.domain)

    st.divider()

    if "session" not in st.session_state:
        st.session_state.session = GraphAuthSession(settings=settings, profile=profile)
    else:
        st.session_state.session.settings = settings
        st.session_state.session.profile = profile
        if profile == AttackProfile.EXTERNAL:
            st.session_state.session.status = AuthStatus.NOT_REQUIRED
        elif demo:
            st.session_state.session.status = AuthStatus.DEMO

    session: GraphAuthSession = st.session_state.session

    if authenticate:
        with st.spinner("Starting MSAL device-code / token flow…"):
            status = session.acquire_token_interactive()
        if status.value == "authenticated":
            st.success(f"Authenticated as {session.account}")
        elif status.value == "demo":
            st.warning("Demo mode or missing client_id — using simulated Graph responses.")
        else:
            st.error(session.error or "Authentication failed")
            if getattr(session, "device_flow_message", None):
                st.code(session.device_flow_message)

    st.caption(f"Auth status: `{session.status.value}` · Read-only probes: `{settings.assessment.read_only}`")

    if start:
        if not selected:
            st.error("Select at least one test category.")
            return
        with st.spinner("Running assessment modules…"):
            engine = AssessmentEngine(settings, session)
            result = engine.run(profile, selected)
            result.ai_summary = AttackPathAnalyzer(settings).summarize(result)
            paths = ReportGenerator(settings).write(result)
            st.session_state.last_result = result
            st.session_state.last_paths = paths

    result = st.session_state.get("last_result")
    if not result:
        st.markdown(
            """
            ### Conceptual dashboard — no assessment run yet
            1. Set the target tenant domain  
            2. Choose **External**, **User**, or **Admin**  
            3. Select categories  
            4. Click **Start Red Team Assessment**  

            Graph maps and validates many controls; separate external modules cover
            auth-flow and exposure checks Graph cannot exercise alone.
            """
        )
        return

    counts = result.severity_counts()
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Critical", counts.get("critical", 0))
    m2.metric("High", counts.get("high", 0))
    m3.metric("Medium", counts.get("medium", 0))
    m4.metric("Low / Info", counts.get("low", 0) + counts.get("info", 0))
    m5.metric("Barriers (pass)", counts.get("pass", 0))

    st.subheader("Attack-path narrative")
    st.write(result.ai_summary)

    st.subheader("Findings")
    for f in result.findings:
        color = SEVERITY_COLORS.get(f.severity, "#475467")
        st.markdown(
            f"""
            <div class="finding-card" style="border-left-color:{color}">
              <div style="font-size:0.72rem;font-weight:700;letter-spacing:0.04em;color:{color}">
                {f.severity.value.upper()} · {f.category.label}
              </div>
              <div style="font-family:Sora,sans-serif;font-weight:650;margin:0.2rem 0">{f.title}</div>
              <div>{f.description}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        with st.expander("Path, barrier & remediation", expanded=False):
            if f.attack_path:
                st.markdown(f"**Attack path:** {f.attack_path}")
            if f.barrier:
                st.markdown(f"**Security barrier:** {f.barrier}")
            if f.remediation:
                st.markdown(f"**Remediation:** {f.remediation}")
            if f.evidence:
                st.json(f.evidence)

    paths = st.session_state.get("last_paths") or {}
    if paths:
        st.subheader("Reports")
        for kind, path in paths.items():
            st.write(f"{kind.upper()}: `{path}`")
            if kind == "html" and Path(path).exists():
                st.download_button(
                    "Download HTML report",
                    data=Path(path).read_text(encoding="utf-8"),
                    file_name=Path(path).name,
                    mime="text/html",
                )


if __name__ == "__main__":
    main()