"""MSAL authentication helpers for Microsoft Graph.

Supports interactive / device-code flows for user & admin profiles.
External profile runs without Graph tokens.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import msal
import requests

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
    profile: AttackProfile
    status: AuthStatus = AuthStatus.UNAUTHENTICATED
    token: str | None = None
    account: dict[str, Any] | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.profile == AttackProfile.EXTERNAL:
            self.status = AuthStatus.NOT_REQUIRED
        elif self.settings.assessment.demo_mode or not self.settings.auth.client_id:
            self.status = AuthStatus.DEMO

    @property
    def authority(self) -> str:
        tenant = self.settings.tenant.tenant_id or "organizations"
        return f"{self.settings.auth.authority.rstrip('/')}/{tenant}"

    def _app(self) -> msal.PublicClientApplication | msal.ConfidentialClientApplication:
        cache_path = Path("token_cache.bin")
        cache = msal.SerializableTokenCache()
        if cache_path.exists():
            cache.deserialize(cache_path.read_text(encoding="utf-8"))

        if self.settings.auth.client_secret:
            app: msal.ClientApplication = msal.ConfidentialClientApplication(
                client_id=self.settings.auth.client_id,
                client_credential=self.settings.auth.client_secret,
                authority=self.authority,
                token_cache=cache,
            )
        else:
            app = msal.PublicClientApplication(
                client_id=self.settings.auth.client_id,
                authority=self.authority,
                token_cache=cache,
            )
        self._cache = cache
        self._cache_path = cache_path
        return app

    def _persist_cache(self) -> None:
        if getattr(self, "_cache", None) and self._cache.has_state_changed:
            self._cache_path.write_text(self._cache.serialize(), encoding="utf-8")

    def acquire_token_interactive(self) -> AuthStatus:
        """Interactive / device-code login for compromised user or admin profiles."""
        if self.profile == AttackProfile.EXTERNAL:
            self.status = AuthStatus.NOT_REQUIRED
            return self.status
        if self.settings.assessment.demo_mode or not self.settings.auth.client_id:
            self.status = AuthStatus.DEMO
            return self.status

        try:
            app = self._app()
            scopes = self.settings.auth.scopes
            accounts = app.get_accounts()
            result = None
            if accounts:
                result = app.acquire_token_silent(scopes, account=accounts[0])
            if not result:
                if isinstance(app, msal.ConfidentialClientApplication):
                    result = app.acquire_token_for_client(scopes=scopes)
                else:
                    flow = app.initiate_device_flow(scopes=scopes)
                    if "user_code" not in flow:
                        raise RuntimeError(f"Device flow failed: {flow}")
                    self.device_flow_message = flow["message"]
                    result = app.acquire_token_by_device_flow(flow)

            if result and "access_token" in result:
                self.token = result["access_token"]
                self.account = {"username": result.get("id_token_claims", {}).get("preferred_username")}
                self.status = AuthStatus.AUTHENTICATED
                self._persist_cache()
            else:
                self.error = (result or {}).get("error_description", "Token acquisition failed")
                self.status = AuthStatus.FAILED
        except Exception as exc:  # noqa: BLE001 — surface to UI
            self.error = str(exc)
            self.status = AuthStatus.FAILED
        return self.status

    def graph_get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.status == AuthStatus.DEMO:
            return {"@demo": True, "value": []}
        if not self.token:
            raise RuntimeError("No Graph access token available")
        url = path if path.startswith("http") else f"https://graph.microsoft.com/v1.0/{path.lstrip('/')}"
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self.token}"},
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()