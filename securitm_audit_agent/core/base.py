# Базовые контракты проверок и статусы аудита.
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping

from securitm_audit_agent.platform.protocols import AuditContextProtocol

if TYPE_CHECKING:
    from securitm_audit_agent.core.report import AuditResult

class Status(str, Enum):
    OK = "OK"
    FAIL = "FAIL"
    ERROR = "ERROR"
    SKIP = "SKIP"


@dataclass(frozen=True)
class CheckMeta:
    check_id: str
    title: str
    description: str
    severity: str
    remediation: str


class BaseCheck(ABC):
    meta: CheckMeta

    def _result(self, status: Status, message: str, evidence: str | None) -> "AuditResult":
        # Локальный импорт убирает runtime-цикл между base.py и report.py.
        from securitm_audit_agent.core.report import AuditResult

        return AuditResult(
            check_id=self.meta.check_id,
            status=status,
            message=message,
            evidence=evidence,
            severity=self.meta.severity,
            remediation=self.meta.remediation,
        )

    @abstractmethod
    def check(self, ctx: AuditContextProtocol, params: Mapping[str, Any]) -> "AuditResult":
        raise NotImplementedError
