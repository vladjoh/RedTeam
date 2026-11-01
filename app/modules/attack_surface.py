"""Attack-surface category — delegates external live recon to ExternalEntraModule."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings
from app.modules.external_entra import ExternalEntraModule


class AttackSurfaceModule(AssessmentModule):
    category = AssessmentCategory.ATTACK_SURFACE
    supported_profiles = {AttackProfile.EXTERNAL, AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        # External (and other profiles selecting this category): prefer live Entra recon.
        # Only fall back to canned demo when explicitly offline and using placeholder domain.
        placeholder = self.tenant.lower() in {
            "customer.onmicrosoft.com",
            "example.onmicrosoft.com",
            "contoso.onmicrosoft.com",
        }
        if self.settings.assessment.demo_mode and placeholder and profile == AttackProfile.EXTERNAL:
            # Still run live probes — public endpoints — then merge a short demo note if live fails empty
            live = ExternalEntraModule(self.settings, self.session).run(profile)
            if live:
                return live
            return demo_findings(profile, [self.category], self.tenant)

        return ExternalEntraModule(self.settings, self.session).run(profile)