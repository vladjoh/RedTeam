"""External Entra module unit tests with mocked HTTP."""

from unittest.mock import MagicMock, patch

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AttackProfile, AssessmentCategory, AssessmentResult, Severity
from app.modules.external_entra import ExternalEntraModule
from app.modules.attack_chains import build_attack_chains, build_likelihood_briefing
from app.reports.generator import ReportGenerator


def test_external_module_with_mocked_http(tmp_path):
    settings = Settings()
    settings.tenant.domain = "contoso.com"
    settings.reporting.output_dir = str(tmp_path)
    settings.reporting.formats = ["html"]
    session = GraphAuthSession(settings=settings)
    module = ExternalEntraModule(settings, session)

    oidc = {
        "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
        "tenant_region_scope": "EU",
    }
    realm = {"NameSpaceType": "Managed", "CloudInstanceName": "microsoftonline.com"}

    def fake_get(url, params=None, timeout=20, allow_redirects=True, headers=None):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 401
        resp.url = url
        resp.content = b"{}"
        resp.text = ""
        resp.headers = {}
        if "openid-configuration" in str(url):
            resp.status_code = 200
            resp.json.return_value = oidc
        elif "getuserrealm" in str(url):
            resp.status_code = 200
            resp.json.return_value = realm
        elif "/_api/web" in str(url):
            resp.status_code = 401
        else:
            resp.json.return_value = {}
        return resp

    def fake_post(url, json=None, timeout=20):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        resp.json.return_value = {"IfExistsResult": 1, "ThrottleStatus": 0}
        return resp

    with patch("app.modules.external_entra.requests.Session") as sess_cls:
        inst = sess_cls.return_value
        inst.headers = {}
        inst.get.side_effect = fake_get
        inst.post.side_effect = fake_post
        with patch("app.modules.external_entra._dns_texts", return_value=[]):
            with patch("dns.resolver.resolve", side_effect=Exception("no dns")):
                findings = module.run(AttackProfile.EXTERNAL)

    assert len(findings) >= 5
    assert any(f.severity == Severity.HIGH for f in findings)

    result = AssessmentResult(
        tenant_domain="contoso.com",
        profile=AttackProfile.EXTERNAL,
        categories=list(AssessmentCategory),
        findings=findings,
        demo_mode=False,
    )
    result.metadata["attack_chains"] = build_attack_chains(result)
    result.metadata["likelihood_briefing"] = build_likelihood_briefing(result)
    paths = ReportGenerator(settings).write(result)
    html = paths["html"].read_text(encoding="utf-8")
    assert "Most likely bypass" in html
    assert result.high_medium_low_counts()["high"] >= 1
