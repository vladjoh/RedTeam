"""Orchestrates assessment modules for a selected profile."""

from __future__ import annotations

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AssessmentCategory, AssessmentResult, AttackProfile
from app.modules.attack_chains import build_attack_chains
from app.modules.attack_surface import AttackSurfaceModule
from app.modules.collaboration import CollaborationModule
from app.modules.identity import IdentitySecurityModule
from app.modules.lateral import LateralMovementModule
from app.modules.mfa_ca import MfaConditionalAccessModule
from app.modules.oauth_apps import OauthEnterpriseAppsModule
from app.modules.persistence import PersistenceRiskModule
from app.modules.privilege import PrivilegeEscalationModule


MODULE_TYPES = [
    AttackSurfaceModule,
    IdentitySecurityModule,
    MfaConditionalAccessModule,
    OauthEnterpriseAppsModule,
    PrivilegeEscalationModule,
    CollaborationModule,
    LateralMovementModule,
    PersistenceRiskModule,
]


class AssessmentEngine:
    def __init__(self, settings: Settings, session: GraphAuthSession) -> None:
        self.settings = settings
        self.session = session
        self.modules = [cls(settings, session) for cls in MODULE_TYPES]

    def run(
        self,
        profile: AttackProfile,
        categories: list[AssessmentCategory] | None = None,
    ) -> AssessmentResult:
        selected = categories or list(AssessmentCategory)
        result = AssessmentResult(
            tenant_domain=self.settings.tenant.domain,
            profile=profile,
            categories=selected,
            demo_mode=self.settings.assessment.demo_mode,
            metadata={
                "auth_status": self.session.status.value,
                "read_only": self.settings.assessment.read_only,
            },
        )

        for module in self.modules:
            if module.category not in selected:
                continue
            if not module.applicable(profile):
                continue
            # External profile: only modules that explicitly support EXTERNAL
            findings = module.run(profile)
            result.findings.extend(findings)

        result.metadata["attack_chains"] = build_attack_chains(result)
        result.mark_finished()
        return result