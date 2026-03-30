# Протоколы для типизации контекста аудита и результата команд.
from __future__ import annotations

import os
from typing import Any, Dict, Optional, Protocol


class CommandResultProtocol(Protocol):
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class AuditContextProtocol(Protocol):
    agent_version: str

    @property
    def host_facts(self) -> Dict[str, Any]: ...

    def read_file(self, path: str) -> Optional[str]: ...

    def stat(self, path: str) -> Optional[os.stat_result]: ...

    def run_cmd(self, args: list[str]) -> CommandResultProtocol: ...
