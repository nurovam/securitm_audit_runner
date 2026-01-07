from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Mapping, Optional

from securitm_audit_agent.core.base import Status
from securitm_audit_agent.core.report import AuditReport, AuditResult
from securitm_audit_agent.core.registry import CheckRegistry


class AuditRunner:
    def __init__(self, registry: CheckRegistry) -> None:
        self._registry = registry

    def run(
        self,
        ctx: object,
        enabled_ids: Optional[Iterable[str]],
        params: Mapping[str, Mapping[str, object]],
    ) -> AuditReport:
        started_at = datetime.now(timezone.utc)
        results: List[AuditResult] = []

        check_ids = list(enabled_ids) if enabled_ids else list(self._registry.ids())

        for check_id in check_ids:
            try:
                check = self._registry.get(check_id)
            except KeyError:
                results.append(
                    AuditResult(
                        check_id=check_id,
                        status=Status.ERROR,
                        message="Check not registered",
                        evidence=None,
                        severity="high",
                        remediation="Register the check or remove it from config",
                    )
                )
                continue

            check_params = params.get(check_id, {})
            try:
                result = check.check(ctx, check_params)
            except Exception as exc:  # noqa: BLE001
                result = AuditResult(
                    check_id=check.meta.check_id,
                    status=Status.ERROR,
                    message=f"Unhandled error: {exc}",
                    evidence=None,
                    severity=check.meta.severity,
                    remediation=check.meta.remediation,
                )
            results.append(result)

        finished_at = datetime.now(timezone.utc)
        return AuditReport(
            host=getattr(ctx, "host_facts", {}),
            started_at=started_at,
            finished_at=finished_at,
            agent_version=getattr(ctx, "agent_version", "0.0.0"),
            results=results,
        )
