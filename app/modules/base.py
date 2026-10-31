"""Base module interface for assessment categories."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.auth.msal_auth import GraphAuthSession
from app.core.config import Settings
from app.core.models import AssessmentCategory, AttackProfile, Finding


class AssessmentModule(ABC):
    category: AssessmentCategory
    supported_profiles: set[AttackProfile]

    def __init__(self, settings: Settings, session: GraphAuthSession) -> None:
        self.settings = settings
        self.session = session
        self.tenant = settings.tenant.domain

    def applicable(self, profile: AttackProfile) -> bool:
        return profile in self.supported_profiles

    @abstractmethod
    def run(self, profile: AttackProfile) -> list[Finding]:
        ...

    def finding(
        self,
        profile: AttackProfile,
        title: str,
        severity,
        description: str,
        *,
        remediation: str = "",
        barrier: str = "",
        attack_path: str = "",
        evidence: dict | None = None,
    ) -> Finding:
        return Finding(
            category=self.category,
            profile=profile,
            title=title,
            severity=severity,
            description=description,
            remediation=remediation,
            barrier=barrier,
            attack_path=attack_path,
            evidence=evidence or {},
        )