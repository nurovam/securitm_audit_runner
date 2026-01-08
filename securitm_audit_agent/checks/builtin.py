from __future__ import annotations

from typing import Mapping, Optional

from securitm_audit_agent.core.base import BaseCheck, CheckMeta, Status
from securitm_audit_agent.core.report import AuditResult


class SshRootLoginCheck(BaseCheck):
    meta = CheckMeta(
        check_id="ssh_root_login",
        title="Disable SSH root login",
        description="Ensure PermitRootLogin is set to 'no' or 'prohibit-password'",
        severity="high",
        remediation="Set PermitRootLogin to 'no' in /etc/ssh/sshd_config and reload sshd",
    )

    def check(self, ctx, params: Mapping[str, object]) -> AuditResult:
        content = ctx.read_file("/etc/ssh/sshd_config")
        if content is None:
            return self._result(Status.SKIP, "sshd_config not readable", None)

        value: Optional[str] = None
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0].lower() == "permitrootlogin":
                value = parts[1].lower()
        if value is None:
            return self._result(Status.FAIL, "PermitRootLogin is not set", None)

        if value in {"no", "prohibit-password"}:
            return self._result(Status.OK, f"PermitRootLogin={value}", value)
        return self._result(Status.FAIL, f"PermitRootLogin={value}", value)

    def _result(self, status: Status, message: str, evidence: Optional[str]) -> AuditResult:
        return AuditResult(
            check_id=self.meta.check_id,
            status=status,
            message=message,
            evidence=evidence,
            severity=self.meta.severity,
            remediation=self.meta.remediation,
        )


class PassMinLenCheck(BaseCheck):
    meta = CheckMeta(
        check_id="pass_min_len",
        title="Password minimum length",
        description="Ensure PASS_MIN_LEN meets the configured minimum",
        severity="medium",
        remediation="Set PASS_MIN_LEN in /etc/login.defs",
    )

    def check(self, ctx, params: Mapping[str, object]) -> AuditResult:
        content = ctx.read_file("/etc/login.defs")
        if content is None:
            return self._result(Status.SKIP, "/etc/login.defs not readable", None)

        min_len = int(params.get("min_len", 12))
        value: Optional[int] = None
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == "PASS_MIN_LEN":
                try:
                    value = int(parts[1])
                except ValueError:
                    value = None
                break

        if value is None:
            return self._result(Status.FAIL, "PASS_MIN_LEN is not set", None)
        if value >= min_len:
            return self._result(Status.OK, f"PASS_MIN_LEN={value}", str(value))
        return self._result(
            Status.FAIL,
            f"PASS_MIN_LEN={value} (required >= {min_len})",
            str(value),
        )

    def _result(self, status: Status, message: str, evidence: Optional[str]) -> AuditResult:
        return AuditResult(
            check_id=self.meta.check_id,
            status=status,
            message=message,
            evidence=evidence,
            severity=self.meta.severity,
            remediation=self.meta.remediation,
        )


class Uid0OnlyRootCheck(BaseCheck):
    meta = CheckMeta(
        check_id="uid0_only_root",
        title="Only root has UID 0",
        description="Ensure no extra UID 0 accounts exist",
        severity="high",
        remediation="Remove or change UID of extra UID 0 accounts",
    )

    def check(self, ctx, params: Mapping[str, object]) -> AuditResult:
        content = ctx.read_file("/etc/passwd")
        if content is None:
            return self._result(Status.SKIP, "/etc/passwd not readable", None)

        uid0 = []
        for line in content.splitlines():
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) < 3:
                continue
            username = parts[0]
            uid = parts[2]
            if uid == "0":
                uid0.append(username)

        if uid0 == ["root"]:
            return self._result(Status.OK, "Only root has UID 0", "root")
        return self._result(Status.FAIL, f"UID 0 accounts: {', '.join(uid0)}", ",".join(uid0))

    def _result(self, status: Status, message: str, evidence: Optional[str]) -> AuditResult:
        return AuditResult(
            check_id=self.meta.check_id,
            status=status,
            message=message,
            evidence=evidence,
            severity=self.meta.severity,
            remediation=self.meta.remediation,
        )


def register_builtin_checks(registry) -> None:
    registry.register(SshRootLoginCheck())
    registry.register(PassMinLenCheck())
    registry.register(Uid0OnlyRootCheck())
