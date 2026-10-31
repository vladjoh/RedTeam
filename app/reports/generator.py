"""HTML / PDF report generation."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import Settings
from app.core.models import AssessmentResult


class ReportGenerator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.template_dir = Path(__file__).parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render_html(self, result: AssessmentResult) -> str:
        template = self.env.get_template("report.html")
        return template.render(
            result=result,
            org=self.settings.reporting.organization,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
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

        if "pdf" in self.settings.reporting.formats:
            pdf_path = out_dir / f"{stem}.pdf"
            try:
                from weasyprint import HTML

                HTML(string=html, base_url=str(self.template_dir)).write_pdf(str(pdf_path))
                paths["pdf"] = pdf_path
            except Exception:
                # PDF is optional on machines without WeasyPrint system libs
                pass

        return paths