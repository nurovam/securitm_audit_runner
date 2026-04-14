# Тесты CLI-хелперов для синхронизации задач.
from __future__ import annotations

import json
import logging
from types import SimpleNamespace

from securitm_audit_agent.cli import _sync_fail_tasks, _write_unsynced_tasks
from securitm_audit_agent.core import Status


class FakeTaskClient:
    def __init__(self, created: bool) -> None:
        self.created = created
        self.payloads = []

    def create_task_if_missing(self, payload):
        self.payloads.append(payload)
        return {"uuid": "task-1"}, self.created


def test_sync_fail_tasks_logs_created_task(caplog) -> None:
    report = SimpleNamespace(
        results=[
            SimpleNamespace(
                check_id="check_created",
                status=Status.FAIL,
                message="msg",
                evidence="evidence",
                remediation="fix",
                severity="high",
            )
        ]
    )
    client = FakeTaskClient(created=True)

    with caplog.at_level(logging.INFO):
        _sync_fail_tasks(client, report, {"author_name": "agent"}, {"hostname": "host"}, "asset-1")

    assert "Created task for check_created" in caplog.text
    assert len(client.payloads) == 1


def test_sync_fail_tasks_logs_existing_task_without_false_success(caplog) -> None:
    report = SimpleNamespace(
        results=[
            SimpleNamespace(
                check_id="check_existing",
                status=Status.FAIL,
                message="msg",
                evidence="evidence",
                remediation="fix",
                severity="high",
            )
        ]
    )
    client = FakeTaskClient(created=False)

    with caplog.at_level(logging.INFO):
        _sync_fail_tasks(client, report, {"author_name": "agent"}, {"hostname": "host"}, "asset-1")

    assert "Task for check_existing already exists and is still open; skipping duplicate creation" in caplog.text
    assert "Created task for check_existing" not in caplog.text
    assert len(client.payloads) == 1


class FailingTaskClient:
    def create_task_if_missing(self, payload):
        raise RuntimeError("api failed")


def test_sync_fail_tasks_returns_unsynced_payloads_on_error(caplog) -> None:
    report = SimpleNamespace(
        results=[
            SimpleNamespace(
                check_id="check_failed",
                status=Status.FAIL,
                message="msg",
                evidence="evidence",
                remediation="fix",
                severity="high",
            )
        ]
    )
    client = FailingTaskClient()

    with caplog.at_level(logging.ERROR):
        unsynced = _sync_fail_tasks(client, report, {"author_name": "agent"}, {"hostname": "host"}, "asset-1")

    assert len(unsynced) == 1
    assert unsynced[0]["check_id"] == "check_failed"
    assert unsynced[0]["payload"]["assets"] == ["asset-1"]
    assert "api failed" in unsynced[0]["error"]
    assert "Failed to sync task for check_failed" in caplog.text


def test_write_unsynced_tasks_writes_json_file(tmp_path) -> None:
    output_path = tmp_path / "tasks.json"
    tasks = [{"check_id": "check-1", "payload": {"name": "Task 1"}, "error": "boom"}]

    _write_unsynced_tasks(str(output_path), tasks)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["tasks"][0]["check_id"] == "check-1"
