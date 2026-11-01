"""HTML / PDF report generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import Settings
from app.core.models import AssessmentResult
from app.modules.attack_chains import build_attack_chains, build_likelihood_briefing


class ReportGenerator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.env.filters["tojson"] = lambda v, indent=None: json.dumps(v, indent=indent, default=str)

    def _fingerprint(self, result: AssessmentResult) -> dict:
        for f in result.findings:
            fp = (f.evidence or {}).get("fingerprint")
            if isinstance(fp, dict):
                return fp
        return {}

    def render_html(self, result: AssessmentResult) -> str:
        template = self.env.get_template("report.html")
        chains = result.metadata.get("attack_chains") or build_attack_chains(result)
        briefing = result.metadata.get("likelihood_briefing") or build_likelihood_briefing(result)
        return template.render(
            result=result,
            org=self.settings.reporting.organization,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            chains=chains,
            briefing=briefing,
            fingerprint=self._fingerprint(result),
        )

    def write(self, result: AssessmentResult) -> dict[str, Path]:
        out_dir = Path(self.settings.reporting.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = f"{result.run_id}_{result.profile.value}_{result.tenant_domain.replace('.', '_')}"
        paths: dict[str, Path] = {}

        html = self.render_html(result)
        html_path = out_dir / f"{stem}.html"
        html_path.write_text(html, encoding="utf-8")
        paths["html"] = html_path

        # Machine-readable companion
        json_path = out_dir / f"{stem}.json"
        json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        paths["json"] = json_path

        if "pdf" in self.settings.reporting.formats:
            pdf_path = out_dir / f"{stem}.pdf"
            try:
                from weasyprint import HTML

                HTML(string=html, base_url=str(self.template_dir)).write_pdf(str(pdf_path))
                paths["pdf"] = pdf_path
            except Exception:
                pass

        return paths