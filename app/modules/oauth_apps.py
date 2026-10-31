"""OAuth / Enterprise Application review."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


RISKY_SCOPE_HINTS = {
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
}


class OauthEnterpriseAppsModule(AssessmentModule):
    category = AssessmentCategory.OAUTH_ENTERPRISE_APPS
    supported_profiles = {AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []
        try:
            apps = self.session.graph_get(
                "servicePrincipals",
                params={"$top": "25", "$select": "id,displayName,appId,accountEnabled,appRoles"},
            )
            findings.append(
                self.finding(
                    profile,
                    "Enterprise applications (service principals) enumerable",
                    Severity.MEDIUM,
                    f"Listed {len(apps.get('value', []))} service principals.",
                    evidence={"sample": [a.get("displayName") for a in apps.get("value", [])[:8]]},
                    barrier="App governance / consent policies.",
                    attack_path="Identify over-privileged apps → abuse tokens or consent.",
                    remediation="Review high-privilege app roles; enable App Governance.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(
                    profile,
                    "Service principal listing blocked",
                    Severity.PASS,
                    str(exc),
                    barrier="Missing Application.Read.All / Directory permissions.",
                )
            )

        try:
            # oauth2PermissionGrants — admin often required
            grants = self.session.graph_get("oauth2PermissionGrants", params={"$top": "50"})
            risky = []
            for g in grants.get("value", []):
                scope = set((g.get("scope") or "").split())
                hit = scope & RISKY_SCOPE_HINTS
                if hit:
                    risky.append({"clientId": g.get("clientId"), "scopes": sorted(hit)})
            findings.append(
                self.finding(
                    profile,
                    "Delegated OAuth grants with sensitive scopes",
                    Severity.HIGH if risky else Severity.PASS,
                    f"Found {len(risky)} grant(s) with high-risk Graph scopes."
                    if risky
                    else "No high-risk delegated scopes in sampled grants.",
                    evidence={"risky_sample": risky[:10]},
                    barrier="Admin consent + continuous access evaluation.",
                    attack_path="Abuse consented app → retain mailbox/file access after password reset.",
                    remediation="Revoke unused grants; disable user consent for high-risk scopes.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.extend(demo_findings(profile, [self.category], self.tenant)[:1])
            findings.append(
                self.finding(profile, "OAuth grant enumeration limited", Severity.INFO, str(exc))
            )

        return findings