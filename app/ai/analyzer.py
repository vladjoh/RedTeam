"""Executive narrative for external scans."""

from __future__ import annotations

from app.core.config import Settings
from app.core.models import AssessmentResult, Severity
from app.modules.attack_chains import build_attack_chains, build_likelihood_briefing


class AttackPathAnalyzer:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def summarize(self, result: AssessmentResult) -> str:
        if self.settings.openai.enabled and self.settings.openai.api_key:
            try:
                from openai import OpenAI

                client = OpenAI(api_key=self.settings.openai.api_key)
                blob = "\n".join(
                    f"- [{f.severity.value}/{f.likelihood.value}] {f.title}: {f.why or f.description}"
                    for f in result.findings[:50]
                )
                prompt = (
                    "Write a concise external Entra assessment narrative (max 220 words). "
                    "Lead with the most likely bypass path and why. Then mention less likely paths. "
                    "Use only the findings. Remind to verify on the authorized tenant.\n\n"
                    f"Tenant: {result.tenant_domain}\nFindings:\n{blob}"
                )
                resp = client.chat.completions.create(
                    model=self.settings.openai.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                )
                return (resp.choices[0].message.content or "").strip()
            except Exception as exc:  # noqa: BLE001
                return self._heuristic(result) + f"\n\n(AI unavailable: {exc})"
        return self._heuristic(result)

    def _heuristic(self, result: AssessmentResult) -> str:
        briefing = result.metadata.get("likelihood_briefing") or build_likelihood_briefing(result)
        chains = result.metadata.get("attack_chains") or build_attack_chains(result)
        counts = briefing.get("counts") or result.high_medium_low_counts()
        most = briefing.get("most_likely_bypass") or {}
        lines = [
            f"External scan of {result.tenant_domain}: "
            f"{counts.get('high', 0)} High, {counts.get('medium', 0)} Medium, {counts.get('low', 0)} Low.",
            f"Most likely bypass: {most.get('summary', chains[0]['name'] if chains else 'n/a')}.",
        ]
        if most.get("why"):
            lines.append(most["why"])
        high = [f for f in result.findings if f.severity == Severity.HIGH][:3]
        if high:
            lines.append("Top High items: " + "; ".join(f.title for f in high) + ".")
        lines.append(
            "Less likely items are informational or already blocked from this vantage point — still verify. "
            "Notify stakeholders and confirm findings on the authorized tenant before remediating."
        )
        return " ".join(lines)