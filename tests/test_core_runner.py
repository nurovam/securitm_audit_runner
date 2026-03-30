# Тесты ядра выполнения проверок и отчёта.
from __future__ import annotations

from typing import Mapping

from securitm_audit_agent.core import AuditRunner, CheckMeta, CheckRegistry, Status
from securitm_audit_agent.core.base import BaseCheck
from tests.helpers import FakeContext


class OkCheck(BaseCheck):
    meta = CheckMeta(
        check_id="ok_check",
        title="OK check",
        description="Returns OK",
        severity="low",
        remediation="None",
    )

    def check(self, ctx, params: Mapping[str, object]):
        return self._result(Status.OK, "ok", None)


class BoomCheck(BaseCheck):
    meta = CheckMeta(
        check_id="boom_check",
        title="Boom check",
        description="Raises error",
        severity="high",
        remediation="Fix boom",
    )

    def check(self, ctx, params: Mapping[str, object]):
        raise RuntimeError("boom")


def test_runner_marks_unknown_check_as_error() -> None:
    registry = CheckRegistry()
    runner = AuditRunner(registry)

    report = runner.run(FakeContext(), ["missing_check"], {})

    assert len(report.results) == 1
    assert report.results[0].check_id == "missing_check"
    assert report.results[0].status == Status.ERROR
    assert report.results[0].message == "Check not registered"


def test_runner_wraps_check_exception_as_error() -> None:
    registry = CheckRegistry()
    registry.register(BoomCheck())
    runner = AuditRunner(registry)

    report = runner.run(FakeContext(), ["boom_check"], {})

    assert len(report.results) == 1
    assert report.results[0].status == Status.ERROR
    assert "boom" in report.results[0].message


def test_registry_error_contains_available_checks() -> None:
    registry = CheckRegistry()
    registry.register(OkCheck())

    try:
        registry.get("missing_check")
    except KeyError as exc:
        message = str(exc)
    else:  # pragma: no cover
        raise AssertionError("Expected KeyError for missing check")

    assert "missing_check" in message
    assert "ok_check" in message


def test_report_contains_duration_seconds() -> None:
    registry = CheckRegistry()
    registry.register(OkCheck())
    runner = AuditRunner(registry)

    report = runner.run(FakeContext(), ["ok_check"], {})
    payload = report.to_dict()

    assert "duration_seconds" in payload
    assert payload["duration_seconds"] >= 0
