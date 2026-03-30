# Генерация PDF-отчета на русском языке.
from __future__ import annotations

from pathlib import Path
from typing import List, Optional
from xml.sax.saxutils import escape

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from securitm_audit_agent.core.report import AuditReport


FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "C:/Windows/Fonts/arial.ttf",
    "C:/Windows/Fonts/calibri.ttf",
]


def _escape(value: object) -> str:
    return escape(str(value or ""))


def _build_story(report: AuditReport, font_name: str) -> List[object]:
    host = report.host or {}
    title_style = ParagraphStyle(
        "AuditTitle",
        fontName=font_name,
        fontSize=15,
        leading=18,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "AuditBody",
        fontName=font_name,
        fontSize=10,
        leading=13,
        spaceAfter=4,
    )
    section_style = ParagraphStyle(
        "AuditSection",
        fontName=font_name,
        fontSize=11,
        leading=14,
        spaceAfter=6,
    )

    story: List[object] = [
        Paragraph("Отчёт аудита", title_style),
        Paragraph(f"Хост: {_escape(host.get('hostname'))}", body_style),
        Paragraph(f"FQDN: {_escape(host.get('fqdn'))}", body_style),
        Paragraph(f"IP: {_escape(host.get('ip'))}", body_style),
        Paragraph(f"Начало: {_escape(report.started_at.isoformat())}", body_style),
        Paragraph(f"Окончание: {_escape(report.finished_at.isoformat())}", body_style),
        Paragraph(f"Длительность: {_escape(report.duration_seconds)} сек.", body_style),
        Paragraph(f"Версия агента: {_escape(report.agent_version)}", body_style),
        Spacer(1, 8),
        Paragraph("Результаты", section_style),
    ]

    for result in report.results:
        story.append(Paragraph(f"<b>[{_escape(result.status.value)}] {_escape(result.check_id)}</b>", body_style))
        story.append(Paragraph(f"Сообщение: {_escape(result.message)}", body_style))
        if result.evidence:
            story.append(Paragraph(f"Доказательства: {_escape(result.evidence)}", body_style))
        if result.remediation:
            story.append(Paragraph(f"Рекомендации: {_escape(result.remediation)}", body_style))
        story.append(Spacer(1, 6))

    return story


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

    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40,
    )
    doc.build(_build_story(report, "AuditFont"))
