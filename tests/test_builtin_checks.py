# Тесты встроенных проверок Linux.
from __future__ import annotations

from securitm_audit_agent.checks.builtin import SshRootLoginCheck, Uid0OnlyRootCheck
from securitm_audit_agent.core import Status
from tests.helpers import FakeContext


def test_ssh_root_login_passes_when_disabled() -> None:
    ctx = FakeContext(
        files={
            "/etc/ssh/sshd_config": """
            # comment
            PermitRootLogin no
            """,
        }
    )

    result = SshRootLoginCheck().check(ctx, {})

    assert result.status == Status.OK
    assert result.evidence == "no"


def test_uid0_only_root_fails_for_extra_uid0_user() -> None:
    ctx = FakeContext(
        files={
            "/etc/passwd": "\n".join(
                [
                    "root:x:0:0:root:/root:/bin/bash",
                    "admin:x:0:0:admin:/home/admin:/bin/bash",
                ]
            )
        }
    )

    result = Uid0OnlyRootCheck().check(ctx, {})

    assert result.status == Status.FAIL
    assert "admin" in (result.evidence or "")
