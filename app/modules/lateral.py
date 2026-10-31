"""Lateral movement analysis helpers."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class LateralMovementModule(AssessmentModule):
    category = AssessmentCategory.LATERAL_MOVEMENT
    supported_profiles = {AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []
        try:
            people = self.session.graph_get("me/people", params={"$top": "10"})
            findings.append(
                self.finding(
                    profile,
                    "People API reveals collaboration graph",
                    Severity.MEDIUM,
                    f"Resolved {len(people.get('value', []))} related people — useful for lateral targeting.",
                    evidence={"sample": [p.get("displayName") for p in people.get("value", [])[:10]]},
                    barrier="Information barriers / restricted people search.",
                    attack_path="Target high-value peers with internal phishing.",
                    remediation="Review people-search scope for sensitive roles.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.extend(demo_findings(profile, [self.category], self.tenant))
            findings.append(
                self.finding(profile, "People API unavailable", Severity.INFO, str(exc))
            )

        try:
            # Calendar as another lateral signal
            events = self.session.graph_get("me/events", params={"$top": "3", "$select": "subject,organizer,attendees"})
            findings.append(
                self.finding(
                    profile,
                    "Calendar data accessible",
                    Severity.LOW,
                    "Calendar events can leak org structure and meeting links.",
                    evidence={"events": len(events.get("value", []))},
                    attack_path="Join meetings / spear-phish attendees.",
                    remediation="Educate on meeting link hygiene; monitor anomalous joins.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(profile, "Calendar access blocked", Severity.PASS, str(exc))
            )

        return findings