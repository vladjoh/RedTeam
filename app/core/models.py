"""Shared domain models for assessment runs."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AttackProfile(str, Enum):
    EXTERNAL = "external"

    @property
    def label(self) -> str:
        return "External Entra scan"

    @property
    def description(self) -> str:
        return (
            "No login. Live public reconnaissance of an Entra / Microsoft 365 domain: "
            "fingerprint, federation, user-enum APIs, mail DNS, M365 services, MFA gaps, "
            "and likely bypass paths."
        )


class AssessmentCategory(str, Enum):
    ATTACK_SURFACE = "attack_surface"
    IDENTITY_SECURITY = "identity_security"
    MFA_CONDITIONAL_ACCESS = "mfa_conditional_access"
    OAUTH_ENTERPRISE_APPS = "oauth_enterprise_apps"
    SHAREPOINT_EXCHANGE_TEAMS = "sharepoint_exchange_teams"
    DNS_MAIL = "dns_mail"
    AZURE_EDGE = "azure_edge"

    @property
    def label(self) -> str:
        return {
            AssessmentCategory.ATTACK_SURFACE: "Tenant & federation",
            AssessmentCategory.IDENTITY_SECURITY: "Identity enumeration",
            AssessmentCategory.MFA_CONDITIONAL_ACCESS: "MFA / auth gaps",
            AssessmentCategory.OAUTH_ENTERPRISE_APPS: "OAuth / device code",
            AssessmentCategory.SHAREPOINT_EXCHANGE_TEAMS: "M365 services",
            AssessmentCategory.DNS_MAIL: "DNS / mail",
            AssessmentCategory.AZURE_EDGE: "Azure edge / takeover hints",
        }[self]


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"

    @property
    def label(self) -> str:
        return self.value.upper()


class Likelihood(str, Enum):
    MOST_LIKELY = "most_likely"
    POSSIBLE = "possible"
    LESS_LIKELY = "less_likely"

    @property
    def label(self) -> str:
        return {
            Likelihood.MOST_LIKELY: "Most likely bypass",
            Likelihood.POSSIBLE: "Possible path",
            Likelihood.LESS_LIKELY: "Less likely",
        }[self]


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4())[:8])
    category: AssessmentCategory
    profile: AttackProfile = AttackProfile.EXTERNAL
    title: str
    severity: Severity
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    barrier: str = ""
    attack_path: str = ""
    likelihood: Likelihood = Likelihood.POSSIBLE
    why: str = ""
    phase: str = ""


class AssessmentResult(BaseModel):
    run_id: str = Field(default_factory=lambda: str(uuid4())[:12])
    tenant_domain: str
    profile: AttackProfile = AttackProfile.EXTERNAL
    categories: list[AssessmentCategory] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    demo_mode: bool = False
    findings: list[Finding] = Field(default_factory=list)
    ai_summary: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def high_medium_low_counts(self) -> dict[str, int]:
        return {
            "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
        }

    def mark_finished(self) -> None:
        self.finished_at = datetime.now(timezone.utc)