"""External Entra module unit tests (network-light with mocks)."""

from unittest.mock import MagicMock, patch

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AttackProfile
from app.modules.external_entra import ExternalEntraModule
from app.modules.attack_chains import build_attack_chains
from app.modules.engine import AssessmentEngine
from app.reports.generator import ReportGenerator


def _settings() -> Settings:
    s = Settings()
    s.assessment.demo_mode = False
    s.tenant.domain = "contoso.onmicrosoft.com"
    s.reporting.formats = ["html"]
    return s


def test_external_module_with_mocked_http(tmp_path):
    settings = _settings()
    settings.reporting.output_dir = str(tmp_path)
    session = GraphAuthSession(settings=settings, profile=AttackProfile.EXTERNAL)
    module = ExternalEntraModule(settings, session)

    oidc = {
        "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
        "tenant_region_scope": "EU",
        "token_endpoint": "https://login.microsoftonline.com/common/oauth2/token",
    }
    realm = {
        "NameSpaceType": "Managed",
        "CloudInstanceName": "microsoftonline.com",
        "FederationBrandName": "Contoso",
    }
    gct = {"IfExistsResult": 1, "ThrottleStatus": 0, "PrefCredential": 1}

    def fake_get(url, params=None, timeout=20, allow_redirects=True):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        resp.url = url
        resp.content = b"<EntityDescriptor entityID='x'/>"
        resp.text = "companyDisplayName Contoso"
        if "openid-configuration" in url:
            resp.json.return_value = oidc
        elif "getuserrealm" in url:
            resp.json.return_value = realm
        else:
            resp.json.return_value = {}
        return resp

    def fake_post(url, json=None, timeout=20):
        resp = MagicMock()
        resp.ok = True
        resp.status_code = 200
        resp.json.return_value = gct
        return resp

    with patch("app.modules.external_entra.requests.Session") as sess_cls:
        inst = sess_cls.return_value
        inst.headers = {}
        inst.get.side_effect = fake_get
        inst.post.side_effect = fake_post
        with patch("app.modules.external_entra._dns_texts", return_value=[]):
            findings = module.run(AttackProfile.EXTERNAL)

    assert len(findings) >= 4
    assert any("fingerprint" in f.title.lower() or "footprint" in f.title.lower() for f in findings)

    engine_result = AssessmentEngine(settings, session)
    # Don't re-hit network: craft result via module findings
    from app.core.models import AssessmentCategory, AssessmentResult

    result = AssessmentResult(
        tenant_domain=settings.tenant.domain,
        profile=AttackProfile.EXTERNAL,
        categories=[AssessmentCategory.ATTACK_SURFACE],
        demo_mode=False,
        findings=findings,
    )
    result.metadata["attack_chains"] = build_attack_chains(result)
    result.mark_finished()
    paths = ReportGenerator(settings).write(result)
    html = paths["html"].read_text(encoding="utf-8")
    assert "External Entra assessment report" in html
    assert "Likely attack chains" in html
    assert "Authorized use only" in html


def test_engine_user_demo_still_works():
    settings = Settings()
    settings.assessment.demo_mode = True
    settings.tenant.domain = "customer.onmicrosoft.com"
    session = GraphAuthSession(settings=settings, profile=AttackProfile.USER)
    result = AssessmentEngine(settings, session).run(AttackProfile.USER)
    assert result.findings
    assert result.metadata.get("attack_chains")