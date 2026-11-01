"""MFA / Conditional Access posture (Graph policy reads where permitted)."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class MfaConditionalAccessModule(AssessmentModule):
    category = AssessmentCategory.MFA_CONDITIONAL_ACCESS
    supported_profiles = {AttackProfile.EXTERNAL, AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if profile == AttackProfile.EXTERNAL:
            return []
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []
        try:
            # Requires Policy.Read.All — often admin-only
            policies = self.session.graph_get("identity/conditionalAccess/policies")
            items = policies.get("value", [])
            enabled = [p for p in items if p.get("state") == "enabled"]
            findings.append(
                self.finding(
                    profile,
                    "Conditional Access policies readable",
                    Severity.INFO if enabled else Severity.HIGH,
                    f"{len(enabled)} enabled / {len(items)} total CA policies visible to this principal.",
                    evidence={"enabled_count": len(enabled), "names": [p.get("displayName") for p in enabled[:10]]},
                    barrier="Conditional Access enforcement at sign-in.",
                    remediation="Ensure MFA and compliant device grants cover all users and apps.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(
                    profile,
                    "Conditional Access policies not readable",
                    Severity.PASS if profile == AttackProfile.USER else Severity.MEDIUM,
                    f"Could not read CA policies (expected for standard users): {exc}",
                    barrier="Least-privilege Graph scopes prevented policy disclosure.",
                )
            )
            findings.extend(demo_findings(profile, [self.category], self.tenant)[:1])

        return findings