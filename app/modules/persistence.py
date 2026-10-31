"""Persistence risk assessment (read-only)."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class PersistenceRiskModule(AssessmentModule):
    category = AssessmentCategory.PERSISTENCE_RISK
    supported_profiles = {AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []

        if profile == AttackProfile.USER:
            try:
                rules = self.session.graph_get("me/mailFolders/inbox/messageRules")
                findings.append(
                    self.finding(
                        profile,
                        "Inbox rules readable — persistence vector",
                        Severity.MEDIUM if rules.get("value") else Severity.LOW,
                        f"Found {len(rules.get('value', []))} inbox rule(s).",
                        evidence={"rules": [r.get("displayName") for r in rules.get("value", [])[:10]]},
                        barrier="Mailbox auditing alerts on forwarding rules.",
                        attack_path="Hidden forward rule → silent mail exfiltration.",
                        remediation="Alert on external forwarding; purge rogue rules during IR.",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                findings.extend(demo_findings(profile, [self.category], self.tenant))
                findings.append(
                    self.finding(profile, "Inbox rules not readable", Severity.INFO, str(exc))
                )

        if profile == AttackProfile.ADMIN:
            try:
                apps = self.session.graph_get(
                    "applications",
                    params={"$top": "15", "$select": "id,displayName,passwordCredentials,keyCredentials"},
                )
                with_secrets = [
                    a
                    for a in apps.get("value", [])
                    if a.get("passwordCredentials") or a.get("keyCredentials")
                ]
                findings.append(
                    self.finding(
                        profile,
                        "Application credentials visible to admin",
                        Severity.CRITICAL if with_secrets else Severity.HIGH,
                        f"{len(with_secrets)} app(s) expose credential metadata (secrets/certs).",
                        evidence={
                            "apps_with_creds": [
                                {"name": a.get("displayName"), "secrets": len(a.get("passwordCredentials") or [])}
                                for a in with_secrets[:10]
                            ]
                        },
                        barrier="App Governance + alerts on new credentials.",
                        attack_path="Add new client secret → long-lived Graph persistence.",
                        remediation="Monitor ApplicationCredentialEvent; rotate and minimize secrets.",
                    )
                )
            except Exception as exc:  # noqa: BLE001
                findings.extend(demo_findings(profile, [self.category], self.tenant))
                findings.append(
                    self.finding(profile, "Application credential audit failed", Severity.INFO, str(exc))
                )

        return findings