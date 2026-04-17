# Тесты базового плагина met_rekom_linux.
from __future__ import annotations

from securitm_audit_agent.core import Status
from securitm_audit_agent.plugins.met_rekom_linux import (
    MetHomeDirsPermsCheck,
    MetPasswdGroupShadowPermsCheck,
    MetSystemCronPermsCheck,
)
from tests.helpers import FakeContext


def test_system_cron_check_scans_files_inside_cron_directories() -> None:
    ctx = FakeContext(
        modes={
            "/etc/crontab": 0o644,
            "/etc/cron.d": 0o755,
            "/etc/cron.hourly": 0o755,
            "/etc/cron.daily": 0o755,
            "/etc/cron.weekly": 0o755,
            "/etc/cron.monthly": 0o755,
            "/etc/cron.daily/backup": 0o775,
        },
        directories={
            "/etc/cron.d": [],
            "/etc/cron.hourly": [],
            "/etc/cron.daily": ["backup"],
            "/etc/cron.weekly": [],
            "/etc/cron.monthly": [],
        },
    )

    result = MetSystemCronPermsCheck().check(ctx, {})

    assert result.status == Status.FAIL
    assert "/etc/cron.daily/backup" in (result.evidence or "")


def test_passwd_group_shadow_check_accepts_standard_secure_modes() -> None:
    ctx = FakeContext(
        modes={
            "/etc/passwd": 0o100644,
            "/etc/group": 0o100644,
            "/etc/shadow": 0o100600,
        }
    )

    result = MetPasswdGroupShadowPermsCheck().check(ctx, {})

    assert result.status == Status.OK


def test_home_dirs_check_ignores_system_accounts() -> None:
    ctx = FakeContext(
        files={
            "/etc/passwd": "\n".join(
                [
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                    "root:x:0:0:root:/root:/bin/bash",
                    "amir:x:1000:1000:Amir:/home/amir:/bin/bash",
                ]
            )
        },
        modes={
            "/usr/sbin": 0o100755,
            "/root": 0o100700,
            "/home/amir": 0o100700,
        },
    )

    result = MetHomeDirsPermsCheck().check(ctx, {})

    assert result.status == Status.OK
