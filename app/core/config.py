"""Configuration loading for local Windows runs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field


ROOT = Path(__file__).resolve().parents[2]


class TenantSettings(BaseModel):
    domain: str = "customer.onmicrosoft.com"
    tenant_id: str = ""


class AuthSettings(BaseModel):
    client_id: str = ""
    client_secret: str = ""
    authority: str = "https://login.microsoftonline.com"
    scopes: list[str] = Field(default_factory=lambda: ["https://graph.microsoft.com/.default"])


class OpenAISettings(BaseModel):
    api_key: str = ""
    model: str = "gpt-4o-mini"
    enabled: bool = False


class AssessmentSettings(BaseModel):
    default_profile: str = "external"
    categories: list[str] = Field(default_factory=list)
    read_only: bool = True
    demo_mode: bool = False


class ReportingSettings(BaseModel):
    output_dir: str = "output/reports"
    formats: list[str] = Field(default_factory=lambda: ["html", "pdf"])
    organization: str = "Authorized Red Team Assessment"


class Settings(BaseModel):
    tenant: TenantSettings = Field(default_factory=TenantSettings)
    auth: AuthSettings = Field(default_factory=AuthSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    assessment: AssessmentSettings = Field(default_factory=AssessmentSettings)
    reporting: ReportingSettings = Field(default_factory=ReportingSettings)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings(config_path: Path | None = None) -> Settings:
    load_dotenv(ROOT / ".env")
    path = config_path or (ROOT / "config" / "config.yaml")
    example = ROOT / "config" / "config.example.yaml"

    data: dict[str, Any] = {}
    if example.exists():
        data = yaml.safe_load(example.read_text(encoding="utf-8")) or {}
    if path.exists():
        data = _deep_merge(data, yaml.safe_load(path.read_text(encoding="utf-8")) or {})

    # Environment overrides
    env_map = {
        ("tenant", "domain"): os.getenv("M365_TENANT_DOMAIN"),
        ("tenant", "tenant_id"): os.getenv("M365_TENANT_ID"),
        ("auth", "client_id"): os.getenv("M365_CLIENT_ID"),
        ("auth", "client_secret"): os.getenv("M365_CLIENT_SECRET"),
        ("openai", "api_key"): os.getenv("OPENAI_API_KEY"),
        ("openai", "model"): os.getenv("OPENAI_MODEL"),
    }
    for (section, key), value in env_map.items():
        if value:
            data.setdefault(section, {})[key] = value

    demo = os.getenv("M365_DEMO_MODE")
    if demo is not None:
        data.setdefault("assessment", {})["demo_mode"] = demo.lower() in {"1", "true", "yes"}

    return Settings.model_validate(data)