"""SharePoint / Exchange / Teams access surface."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class CollaborationModule(AssessmentModule):
    category = AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS
    supported_profiles = {AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []

        # Mailbox
        try:
            messages = self.session.graph_get("me/messages", params={"$top": "1", "$select": "id,subject"})
            findings.append(
                self.finding(
                    profile,
                    "Mailbox read access confirmed",
                    Severity.MEDIUM,
                    "Caller can read mailbox messages via Graph.",
                    evidence={"sample_count": len(messages.get("value", []))},
                    barrier="Mailbox auditing / DLP / sensitivity labels.",
                    attack_path="Search mailbox for secrets → pivot to other systems.",
                    remediation="Enable mailbox audit; restrict Graph Mail scopes.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(
                    profile,
                    "Mailbox access blocked",
                    Severity.PASS,
                    str(exc),
                    barrier="Missing Mail.Read or CA blocked Graph mail access.",
                )
            )

        # OneDrive / SharePoint via me/drive
        try:
            drive = self.session.graph_get("me/drive/root/children", params={"$top": "5"})
            findings.append(
                self.finding(
                    profile,
                    "OneDrive / personal drive listing permitted",
                    Severity.LOW,
                    f"Listed {len(drive.get('value', []))} root item(s).",
                    evidence={"names": [i.get("name") for i in drive.get("value", [])]},
                    attack_path="Download sensitive files synced from SharePoint libraries.",
                    remediation="Sensitivity labels + conditional access for unmanaged devices.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(profile, "Drive listing blocked", Severity.PASS, str(exc))
            )

        # Joined teams
        try:
            teams = self.session.graph_get("me/joinedTeams")
            findings.append(
                self.finding(
                    profile,
                    "Teams membership visible",
                    Severity.LOW,
                    f"User joined {len(teams.get('value', []))} team(s).",
                    evidence={"teams": [t.get("displayName") for t in teams.get("value", [])[:15]]},
                    attack_path="Mine chat/files for credentials and internal URLs.",
                    remediation="Guest access reviews; restrict external sharing in Teams.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.extend(demo_findings(profile, [self.category], self.tenant)[:1])
            findings.append(
                self.finding(profile, "Teams query failed", Severity.INFO, str(exc))
            )

        return findings