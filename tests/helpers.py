# Вспомогательные тестовые объекты для unit-тестов.
from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Dict, Optional


@dataclass
class FakeCommandResult:
    args: list[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


@dataclass
class FakeContext:
    files: Dict[str, str] = field(default_factory=dict)
    modes: Dict[str, int] = field(default_factory=dict)
    directories: Dict[str, list[str]] = field(default_factory=dict)
    host_facts: Dict[str, str] = field(
        default_factory=lambda: {
            "hostname": "test-host",
            "fqdn": "test-host.local",
            "ip": "127.0.0.1",
        }
    )
    agent_version: str = "test"

    def read_file(self, path: str) -> Optional[str]:
        return self.files.get(path)

    def stat(self, path: str):
        mode = self.modes.get(path)
        if mode is None:
            return None
        return SimpleNamespace(st_mode=mode)

    def list_dir(self, path: str) -> Optional[list[str]]:
        items = self.directories.get(path)
        if items is None:
            return None
        return list(items)

    def run_cmd(self, args: list[str]) -> FakeCommandResult:
        return FakeCommandResult(args=args)
