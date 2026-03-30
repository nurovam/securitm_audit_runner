# Тесты базового плагина met_rekom_linux.
from __future__ import annotations

from securitm_audit_agent.core import Status
from securitm_audit_agent.plugins.met_rekom_linux import MetSystemCronPermsCheck
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
