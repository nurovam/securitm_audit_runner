# Экспорт генераторов отчетов.
from __future__ import annotations

from typing import Optional

from securitm_audit_agent.core.report import AuditReport


def write_pdf_report(report: AuditReport, path: str, font_path: Optional[str] = None) -> None:
    # Импортируем PDF-генератор лениво, чтобы отсутствие reportlab не ломало CLI без PDF.
    from securitm_audit_agent.reporting.pdf import write_pdf_report as _write_pdf_report

    _write_pdf_report(report, path, font_path)


__all__ = ["write_pdf_report"]
