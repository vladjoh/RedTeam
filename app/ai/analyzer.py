"""Optional OpenAI-based attack-path narrative."""

from __future__ import annotations

from app.core.config import Settings
from app.core.models import AssessmentResult, AttackProfile
from app.modules.attack_chains import build_attack_chains


class AttackPathAnalyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def summarize(self, result: AssessmentResult) -> str:
        if not self.settings.openai.enabled or not self.settings.openai.api_key:
            return self._heuristic_summary(result)

        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.settings.openai.api_key)
            findings_blob = "\n".join(
                f"- [{f.severity.value}] {f.title}: {f.description} | barrier={f.barrier}"
                for f in result.findings[:40]
            )
            prompt = (
                "You are a Microsoft 365 red-team reporting assistant. "
                "Given findings from an authorized assessment, write a concise executive "
                "attack-path narrative (max 250 words): how far an attacker could get, "
                "which barriers stopped progress, and top 3 remediations. "
                "Remind the reader to verify findings on the authorized tenant. "
                "Do not invent systems not present in the findings.\n\n"
                f"Tenant: {result.tenant_domain}\n"
                f"Profile: {result.profile.label}\n"
                f"Demo mode: {result.demo_mode}\n"
                f"Findings:\n{findings_blob}"
            )
            resp = client.chat.completions.create(
                model=self.settings.openai.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as exc:  # noqa: BLE001
            return self._heuristic_summary(result) + f"\n\n(AI summary unavailable: {exc})"

    def _heuristic_summary(self, result: AssessmentResult) -> str:
        counts = result.severity_counts()
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        chains = result.metadata.get("attack_chains") or build_attack_chains(result)

        lines = [
            f"Assessment profile: {result.profile.label} against {result.tenant_domain}.",
            f"Findings: {len(result.findings)} total ({critical} critical, {high} high).",
        ]
        if result.profile == AttackProfile.EXTERNAL:
            lines.append(
                "External scan used public Entra / M365 endpoints only (no login). "
                "The same signals are available to any attacker who knows the domain."
            )
        elif result.demo_mode:
            lines.append(
                "Demo mode was active for Graph-backed checks — treat Graph findings as illustrative until you authenticate."
            )
        if chains:
            top = chains[0]
            lines.append(
                f"Primary chain to review: {top['name']} ({top['effort']} effort) — "
                + " → ".join(top["steps"][:3])
                + "."
            )
        remediations = [f.remediation for f in result.findings if f.remediation][:3]
        if remediations:
            lines.append("Priority remediations: " + "; ".join(remediations) + ".")
        lines.append("Verify every finding on the authorized target before changing controls.")
        return " ".join(lines)