"""Smoke tests for demo-mode assessment engine."""

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AssessmentCategory, AttackProfile
from app.modules.engine import AssessmentEngine
from app.ai.analyzer import AttackPathAnalyzer
from app.reports.generator import ReportGenerator


def _engine() -> AssessmentEngine:
    settings = Settings()
    settings.assessment.demo_mode = True
    settings.tenant.domain = "customer.onmicrosoft.com"
    session = GraphAuthSession(settings=settings, profile=AttackProfile.EXTERNAL)
    return AssessmentEngine(settings, session)


def test_external_demo_run():
    engine = _engine()
    result = engine.run(
        AttackProfile.EXTERNAL,
        [AssessmentCategory.ATTACK_SURFACE, AssessmentCategory.IDENTITY_SECURITY],
    )
    assert result.demo_mode is True
    assert len(result.findings) >= 1
    assert result.profile == AttackProfile.EXTERNAL


def test_user_and_admin_cover_categories():
    settings = Settings()
    settings.assessment.demo_mode = True
    for profile in (AttackProfile.USER, AttackProfile.ADMIN):
        session = GraphAuthSession(settings=settings, profile=profile)
        engine = AssessmentEngine(settings, session)
        result = engine.run(profile, list(AssessmentCategory))
        assert result.findings
        cats = {f.category for f in result.findings}
        assert AssessmentCategory.PERSISTENCE_RISK in cats or profile == AttackProfile.USER


def test_heuristic_summary_and_html_report(tmp_path):
    settings = Settings()
    settings.assessment.demo_mode = True
    settings.reporting.output_dir = str(tmp_path)
    settings.reporting.formats = ["html"]
    session = GraphAuthSession(settings=settings, profile=AttackProfile.ADMIN)
    result = AssessmentEngine(settings, session).run(AttackProfile.ADMIN)
    result.ai_summary = AttackPathAnalyzer(settings).summarize(result)
    assert "Assessment profile" in result.ai_summary or len(result.ai_summary) > 20
    paths = ReportGenerator(settings).write(result)
    assert paths["html"].exists()
    html = paths["html"].read_text(encoding="utf-8")
    assert "M365 Red Team" in html
    assert "Authorized use only" in html