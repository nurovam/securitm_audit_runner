# Генерация PDF-отчета на русском языке.
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from securitm_audit_agent.core.report import AuditReport


FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
]


def _wrap_text(text: str, width: int) -> List[str]:
    # Примитивный перенос по словам для строк отчета.
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if not current:
            candidate = word
        else:
            candidate = f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
            continue
        if current:
            lines.append(current)
            current = word
        else:
            lines.append(word[:width])
            current = word[width:]
    if current:
        lines.append(current)
    return lines


def _build_lines(report: AuditReport) -> List[str]:
    host = report.host or {}
    lines: List[str] = [
        "Отчет аудита",
        f"Хост: {host.get('hostname') or ''}",
        f"FQDN: {host.get('fqdn') or ''}",
        f"IP: {host.get('ip') or ''}",
        f"Начало: {report.started_at.isoformat()}",
        f"Окончание: {report.finished_at.isoformat()}",
        f"Версия агента: {report.agent_version}",
        "",
        "Результаты:",
    ]

    for result in report.results:
        lines.append(f"- [{result.status.value}] {result.check_id}")
        lines.extend(_wrap_text(f"  сообщение: {result.message}", 90))
        if result.evidence:
            lines.extend(_wrap_text(f"  доказательства: {result.evidence}", 90))
        if result.remediation:
            lines.extend(_wrap_text(f"  рекомендации: {result.remediation}", 90))
        lines.append("")

    return lines


def _resolve_font_path(font_path: Optional[str]) -> str:
    if font_path:
        candidate = Path(font_path)
        if candidate.exists():
            return str(candidate)
        raise FileNotFoundError(f"PDF font not found: {font_path}")

    # Пытаемся найти подходящий кириллический шрифт из известных путей.
    for candidate in FONT_CANDIDATES:
        if Path(candidate).exists():
            return candidate

    raise FileNotFoundError(
        "PDF font not found. Set audit.output.pdf_font_path in config "
        "to a TTF font that supports Cyrillic."
    )


def write_pdf_report(report: AuditReport, path: str, font_path: Optional[str] = None) -> None:
    resolved_font = _resolve_font_path(font_path)
    pdfmetrics.registerFont(TTFont("AuditFont", resolved_font))

    pdf = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    x = 50
    y = height - 50
    line_height = 14

    pdf.setFont("AuditFont", 10)

    for line in _build_lines(report):
        if y < 50:
            # Переход на новую страницу при достижении нижнего поля.
            pdf.showPage()
            pdf.setFont("AuditFont", 10)
            y = height - 50
        pdf.drawString(x, y, line)
        y -= line_height

    pdf.save()
