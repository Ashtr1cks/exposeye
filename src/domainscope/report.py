"""Render scan results to JSON, Markdown and a self-contained HTML report."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from domainscope.utils import SEVERITIES

FORMATS = ("html", "md", "json")

_env = Environment(
    loader=PackageLoader("domainscope", "templates"),
    autoescape=select_autoescape(["html", "j2.html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, default=str)


def _render(template: str, result: dict) -> str:
    return _env.get_template(template).render(r=result, severities=SEVERITIES)


def is_email(result: dict) -> bool:
    return (result.get("meta") or {}).get("kind") == "email"


def report_name(result: dict) -> str:
    """Filesystem-friendly subject: the domain, or the email with @ replaced."""
    meta = result["meta"]
    return meta["email"].replace("@", "_at_") if is_email(result) else meta["domain"]


def to_markdown(result: dict) -> str:
    return _render("email_report.md.j2" if is_email(result) else "report.md.j2", result)


def to_html(result: dict) -> str:
    return _render("email_report.html" if is_email(result) else "report.html", result)


RENDERERS = {"html": to_html, "md": to_markdown, "json": to_json}


def write_reports(result: dict, out_dir: str | Path, formats: list[str]) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{report_name(result)}_{stamp}"
    written = []
    for fmt in formats:
        path = out / f"{base}.{fmt}"
        path.write_text(RENDERERS[fmt](result), encoding="utf-8")
        written.append(path)
    return written
