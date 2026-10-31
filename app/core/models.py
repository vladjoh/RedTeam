"""Shared domain models for assessment runs."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AttackProfile(str, Enum):
    EXTERNAL = "external"
    USER = "user"
    ADMIN = "admin"

    @property
    def label(self) -> str:
        return {
            AttackProfile.EXTERNAL: "External Attacker",
            AttackProfile.USER: "Compromised User",
            AttackProfile.ADMIN: "Compromised Admin",
        }[self]

    @property
    def description(self) -> str:
        return {
            AttackProfile.EXTERNAL: (
                "No authenticated access. Map exposed services, identities, "
                "domains, and possible entry paths."
            ),
            AttackProfile.USER: (
                "Standard user account. Inspect app/data/group access, "
                "SharePoint, Teams, and privilege-escalation opportunities."
            ),
            AttackProfile.ADMIN: (
                "Administrator compromised. Review privileges, app control, "
                "tenant configuration, and blast radius of admin compromise."
            ),
        }[self]


class AssessmentCategory(str, Enum):
    ATTACK_SURFACE = "attack_surface"
    IDENTITY_SECURITY = "identity_security"
    MFA_CONDITIONAL_ACCESS = "mfa_conditional_access"
    OAUTH_ENTERPRISE_APPS = "oauth_enterprise_apps"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SHAREPOINT_EXCHANGE_TEAMS = "sharepoint_exchange_teams"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE_RISK = "persistence_risk"

    @property
    def label(self) -> str:
        return {
            AssessmentCategory.ATTACK_SURFACE: "Attack surface discovery",
            AssessmentCategory.IDENTITY_SECURITY: "Identity security",
            AssessmentCategory.MFA_CONDITIONAL_ACCESS: "MFA / Conditional Access",
            AssessmentCategory.OAUTH_ENTERPRISE_APPS: "OAuth / Enterprise Applications",
            AssessmentCategory.PRIVILEGE_ESCALATION: "Privilege escalation paths",
            AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS: "SharePoint / Exchange / Teams",
            AssessmentCategory.LATERAL_MOVEMENT: "Lateral movement analysis",
            AssessmentCategory.PERSISTENCE_RISK: "Persistence risk assessment",
        }[self]


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    category: AssessmentCategory
    profile: AttackProfile
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    barrier: str = ""  # security control that stops or mitigates this path
    attack_path: str = ""


class AssessmentResult(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4())[:12])
    tenant_domain: str
    profile: AttackProfile
    categories: list[AssessmentCategory]
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    demo_mode: bool = True
    findings: list[Finding] = Field(default_factory=list)
    ai_summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def mark_finished(self) -> None:
        self.finished_at = datetime.now(timezone.utc)