"""Orchestrates the external Entra assessment."""

from __future__ import annotations

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AssessmentCategory, AssessmentResult, AttackProfile
from app.modules.attack_chains import build_attack_chains, build_likelihood_briefing
from app.modules.external_entra import ExternalEntraModule


class AssessmentEngine:
    def __init__(self, settings: Settings, session: GraphAuthSession | None = None) -> None:
        self.settings = settings
        self.session = session or GraphAuthSession(settings=settings, profile=AttackProfile.EXTERNAL)
        self.module = ExternalEntraModule(settings, self.session)

    def run(self, domain: str | None = None) -> AssessmentResult:
        if domain:
            self.settings.tenant.domain = domain.strip()
            self.module.tenant = self.settings.tenant.domain

        result = AssessmentResult(
            tenant_domain=self.settings.tenant.domain,
            profile=AttackProfile.EXTERNAL,
            categories=list(AssessmentCategory),
            demo_mode=False,
            metadata={"read_only": True, "mode": "external_only"},
        )
        result.findings = self.module.run(AttackProfile.EXTERNAL)
        result.metadata["attack_chains"] = build_attack_chains(result)
        result.metadata["likelihood_briefing"] = build_likelihood_briefing(result)
        result.mark_finished()
        return result