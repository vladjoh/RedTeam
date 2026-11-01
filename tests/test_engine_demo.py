"""Smoke tests for external-only engine."""

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AttackProfile
from app.modules.attack_chains import build_likelihood_briefing
from app.modules.engine import AssessmentEngine
from app.ai.analyzer import AttackPathAnalyzer
from app.reports.generator import ReportGenerator
from app.core.models import AssessmentCategory, AssessmentResult, Finding, Likelihood, Severity


def test_likelihood_briefing_and_report(tmp_path):
    settings = Settings()
    settings.tenant.domain = "example.com"
    settings.reporting.output_dir = str(tmp_path)
    settings.reporting.formats = ["html"]

    findings = [
        Finding(
            category=AssessmentCategory.DNS_MAIL,
            title="DMARC missing",
            severity=Severity.HIGH,
            description="No DMARC",
            likelihood=Likelihood.MOST_LIKELY,
            why="Spoofing path",
            phase="dns_mail",
        ),
        Finding(
            category=AssessmentCategory.IDENTITY_SECURITY,
            title="GetCredentialType user-validation API is reachable",
            severity=Severity.HIGH,
            description="API ok",
            likelihood=Likelihood.MOST_LIKELY,
            why="User enum",
            phase="user_enum",
        ),
        Finding(
            category=AssessmentCategory.ATTACK_SURFACE,
            title="Tenant fingerprint confirmed (OpenID)",
            severity=Severity.INFO,
            description="OIDC",
            likelihood=Likelihood.LESS_LIKELY,
            why="Expected",
            phase="tenant",
        ),
    ]
    result = AssessmentResult(
        tenant_domain="example.com",
        profile=AttackProfile.EXTERNAL,
        categories=list(AssessmentCategory),
        findings=findings,
        demo_mode=False,
    )
    result.metadata["likelihood_briefing"] = build_likelihood_briefing(result)
    result.ai_summary = AttackPathAnalyzer(settings).summarize(result)
    assert "High" in result.ai_summary or "high" in result.ai_summary.lower()
    paths = ReportGenerator(settings).write(result)
    html = paths["html"].read_text(encoding="utf-8")
    assert "HIGH" in html
    assert "Most likely bypass" in html
    assert "Authorized use only" in html


def test_engine_constructs():
    settings = Settings()
    settings.tenant.domain = "customer.onmicrosoft.com"
    engine = AssessmentEngine(settings, GraphAuthSession(settings=settings))
    assert engine.module is not None