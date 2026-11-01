"""Auth helpers — external-only product does not require Graph tokens."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.core.config import Settings
from app.core.models import AttackProfile


class AuthStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    DEMO = "demo"
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    FAILED = "failed"


@dataclass
class GraphAuthSession:
    settings: Settings
    profile: AttackProfile = AttackProfile.EXTERNAL
    status: AuthStatus = AuthStatus.NOT_REQUIRED
    token: str | None = None
    account: dict[str, Any] | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        self.status = AuthStatus.NOT_REQUIRED