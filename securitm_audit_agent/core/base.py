from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


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

    @abstractmethod
    def check(self, ctx: Any, params: Mapping[str, Any]) -> "AuditResult":
        raise NotImplementedError


from securitm_audit_agent.core.report import AuditResult  # noqa: E402
