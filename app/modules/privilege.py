"""Privilege escalation path analysis."""

from __future__ import annotations

from app.core.models import AssessmentCategory, AttackProfile, Severity
from app.modules.base import AssessmentModule
from app.modules.demo_data import demo_findings


class PrivilegeEscalationModule(AssessmentModule):
    category = AssessmentCategory.PRIVILEGE_ESCALATION
    supported_profiles = {AttackProfile.USER, AttackProfile.ADMIN}

    def run(self, profile: AttackProfile) -> list:
        if self.settings.assessment.demo_mode:
            return demo_findings(profile, [self.category], self.tenant)

        findings = []
        try:
            # directoryRoles — who holds privileged roles
            roles = self.session.graph_get("directoryRoles")
            privileged_names = []
            for role in roles.get("value", []):
                name = role.get("displayName", "")
                if any(k in name.lower() for k in ("admin", "privileged", "global")):
                    privileged_names.append(name)
            findings.append(
                self.finding(
                    profile,
                    "Privileged directory roles visible",
                    Severity.HIGH if profile == AttackProfile.ADMIN else Severity.MEDIUM,
                    f"Observed {len(privileged_names)} privileged-looking role(s).",
                    evidence={"roles": privileged_names[:20]},
                    barrier="PIM eligible vs active assignments; approval workflows.",
                    attack_path="Compromise role member → tenant-wide control.",
                    remediation="Convert standing admins to PIM-eligible; enforce MFA + CAP.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.append(
                self.finding(
                    profile,
                    "Directory role listing blocked",
                    Severity.PASS,
                    str(exc),
                    barrier="Role management permissions not granted to this principal.",
                )
            )

        try:
            member_of = self.session.graph_get("me/memberOf")
            groups = [
                m.get("displayName")
                for m in member_of.get("value", [])
                if m.get("@odata.type", "").endswith("group")
            ]
            findings.append(
                self.finding(
                    profile,
                    "Group membership footprint for current principal",
                    Severity.INFO,
                    f"Principal is member of {len(groups)} group(s).",
                    evidence={"groups": groups[:25]},
                    attack_path="Nested group → role-assignable group → privilege gain.",
                    remediation="Audit role-assignable groups and owners.",
                )
            )
        except Exception as exc:  # noqa: BLE001
            findings.extend(demo_findings(profile, [self.category], self.tenant)[:1])
            findings.append(
                self.finding(profile, "memberOf query failed", Severity.INFO, str(exc))
            )

        return findings