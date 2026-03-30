# Контекст доступа к данным хоста для проверок.
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional

from securitm_audit_agent.platform.facts import (
    get_fqdn,
    get_hostname,
    get_os_release,
    get_primary_ip,
)


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class AuditContext:
    def __init__(self, agent_version: str) -> None:
        self.agent_version = agent_version
        self._host_facts = self._collect_host_facts()

    @property
    def host_facts(self) -> Dict[str, Any]:
        # Возвращаем копию, чтобы факты нельзя было случайно изменить снаружи.
        return dict(self._host_facts)

    def read_file(self, path: str) -> Optional[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                return handle.read()
        except (FileNotFoundError, PermissionError):
            return None

    def stat(self, path: str) -> Optional[os.stat_result]:
        try:
            return os.stat(path)
        except (FileNotFoundError, PermissionError):
            return None

    def list_dir(self, path: str) -> Optional[list[str]]:
        try:
            return sorted(os.listdir(path))
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            return None

    def run_cmd(self, args: list[str]) -> CommandResult:
        # Унифицированный запуск команд с захватом stdout/stderr.
        completed = subprocess.run(
            args,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return CommandResult(
            args=args,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def _collect_host_facts(self) -> Dict[str, Any]:
        # Сбор базовых сведений о хосте для отчета.
        hostname = get_hostname()
        fqdn = get_fqdn()
        ip_address = get_primary_ip(self.run_cmd)
        os_release = get_os_release(self.read_file)
        return {
            "hostname": hostname,
            "fqdn": fqdn,
            "ip": ip_address,
            "os_release": os_release,
        }
