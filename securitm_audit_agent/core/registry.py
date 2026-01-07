from __future__ import annotations

from typing import Dict, Iterable, List

from securitm_audit_agent.core.base import BaseCheck


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: Dict[str, BaseCheck] = {}

    def register(self, check: BaseCheck) -> None:
        if check.meta.check_id in self._checks:
            raise ValueError(f"Duplicate check_id: {check.meta.check_id}")
        self._checks[check.meta.check_id] = check

    def get(self, check_id: str) -> BaseCheck:
        return self._checks[check_id]

    def all(self) -> List[BaseCheck]:
        return list(self._checks.values())

    def ids(self) -> Iterable[str]:
        return self._checks.keys()
