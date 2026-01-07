from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from securitm_audit_agent.core.base import Status


@dataclass
class AuditResult:
    check_id: str
    status: Status
    message: str
    evidence: Optional[str]
    severity: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "status": self.status.value,
            "message": self.message,
            "evidence": self.evidence,
            "severity": self.severity,
            "remediation": self.remediation,
        }


@dataclass
class AuditReport:
    host: Dict[str, Any]
    started_at: datetime
    finished_at: datetime
    agent_version: str
    results: List[AuditResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "started_at": self.started_at.astimezone(timezone.utc).isoformat(),
            "finished_at": self.finished_at.astimezone(timezone.utc).isoformat(),
            "agent_version": self.agent_version,
            "results": [result.to_dict() for result in self.results],
        }
