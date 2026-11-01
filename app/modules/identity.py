"""Identity security checks via Graph (user/admin) or demo."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class IdentitySecurityModule(AssessmentModule):
    category = AssessmentCategory.IDENTITY_SECURITY
    supported_profiles = {AttackProfile.EXTERNAL, AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        # External identity signals come from the live Entra recon module.
        if profile == AttackProfile.EXTERNAL:
            return []
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []
        try:
            me = self.session.graph_get("me")
            findings.append(
                self.finding(
                    profile,
                    "Authenticated identity context resolved",
                    Severity.INFO,
                    f"Signed in as {me.get('userPrincipalName', me.get('displayName'))}",
                    evidence={"id": me.get("id"), "upn": me.get("userPrincipalName")},
                    barrier="Valid credentials / session required.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(profile, "Unable to resolve /me", Severity.MEDIUM, str(exc))
            )

        try:
            users = self.session.graph_get("users", params={"$top": "5", "$select": "id,displayName,userPrincipalName,accountEnabled"})
            enabled = [u for u in users.get("value", []) if u.get("accountEnabled")]
            findings.append(
                self.finding(
                    profile,
                    "Directory user listing permitted",
                    Severity.MEDIUM if profile == AttackProfile.USER else Severity.INFO,
                    f"Caller can list users (sample size {len(users.get('value', []))}, enabled≈{len(enabled)}).",
                    evidence={"sample": users.get("value", [])[:3]},
                    barrier="Directory visibility / Graph permissions.",
                    attack_path="Enumerate identities → targeted phishing or spray.",
                    remediation="Tighten User.Read.All; prefer least-privilege Graph scopes.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(
                    profile,
                    "User directory listing blocked",
                    Severity.PASS,
                    f"Graph denied or failed user listing: {exc}",
                    barrier="Authorization / CA / missing scope stopped enumeration.",
                )
            )

        return findings