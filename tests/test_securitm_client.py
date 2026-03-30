# Тесты клиента SecurITM, связанные с идемпотентностью задач.
from __future__ import annotations

import requests

from securitm_audit_agent.integrations.securitm import SecurITMClient


def test_create_task_if_missing_returns_existing_task(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    monkeypatch.setattr(
        client,
        "find_open_task",
        lambda name, asset_uuid=None: {"uuid": "task-1", "name": name},
    )
    monkeypatch.setattr(client, "create_task", lambda task_payload: {"uuid": "created"})

    task, created = client.create_task_if_missing(payload)

    assert created is False
    assert task["uuid"] == "task-1"


def test_create_task_if_missing_creates_task_when_listing_forbidden(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    response = requests.Response()
    response.status_code = 403

    def _raise_forbidden(name, asset_uuid=None):
        raise requests.HTTPError("forbidden", response=response)

    monkeypatch.setattr(client, "find_open_task", _raise_forbidden)
    monkeypatch.setattr(client, "create_task", lambda task_payload: {"uuid": "task-created"})

    task, created = client.create_task_if_missing(payload)

    assert created is True
    assert task["uuid"] == "task-created"


def test_create_task_if_missing_creates_task_when_listing_bad_request(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    response = requests.Response()
    response.status_code = 422

    def _raise_bad_request(name, asset_uuid=None):
        raise requests.HTTPError("unprocessable", response=response)

    monkeypatch.setattr(client, "find_open_task", _raise_bad_request)
    monkeypatch.setattr(client, "create_task", lambda task_payload: {"uuid": "task-created"})

    task, created = client.create_task_if_missing(payload)

    assert created is True
    assert task["uuid"] == "task-created"


def test_find_asset_by_name_requests_minimal_fields(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    captured = {}

    def _get_assets(asset_type_slug, fields=None):
        captured["asset_type_slug"] = asset_type_slug
        captured["fields"] = fields
        return [{"uuid": "asset-1", "Hostname": "host-1"}]

    monkeypatch.setattr(client, "get_assets", _get_assets)

    asset = client.find_asset_by_name("computer-1", "host-1", name_field="Hostname")

    assert asset is not None
    assert captured["asset_type_slug"] == "computer-1"
    assert captured["fields"] == ["uuid", "name", "Hostname"]


def test_get_tasks_extracts_data_objects(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    class _Response:
        content = b"1"

        def json(self):
            return {
                "data": {
                    "total": 1,
                    "count": 1,
                    "objects": [{"uuid": "task-1", "name": "Task 1"}],
                }
            }

    monkeypatch.setattr(client.session, "get", lambda *args, **kwargs: _Response())
    monkeypatch.setattr(client, "_raise_for_status", lambda response: None)

    tasks = client.get_tasks()

    assert tasks == [{"uuid": "task-1", "name": "Task 1"}]


def test_create_task_requires_task_object(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    class _Response:
        content = b"1"

        def json(self):
            return {"ok": True}

    monkeypatch.setattr(client.session, "post", lambda *args, **kwargs: _Response())
    monkeypatch.setattr(client, "_raise_for_status", lambda response: None)

    try:
        client.create_task({"name": "Task 1", "is_done": 0})
    except RuntimeError as exc:
        assert "Task creation returned no task object" in str(exc)
    else:
        raise AssertionError("RuntimeError was not raised")


def test_create_task_reposts_after_redirect(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    calls = []

    class _RedirectResponse:
        content = b""
        is_redirect = True
        is_permanent_redirect = False
        headers = {"Location": "/api/v2/tasks/"}

    class _CreatedResponse:
        content = b"1"
        is_redirect = False
        is_permanent_redirect = False
        headers = {}

        def json(self):
            return {"uuid": "task-1", "name": "Task 1"}

    responses = [_RedirectResponse(), _CreatedResponse()]

    def _post(url, **kwargs):
        calls.append(url)
        return responses.pop(0)

    monkeypatch.setattr(client.session, "post", _post)
    monkeypatch.setattr(client, "_raise_for_status", lambda response: None)

    created = client.create_task({"name": "Task 1", "is_done": 0})

    assert created["uuid"] == "task-1"
    assert calls == [
        "https://example.test/api/v2/tasks",
        "https://example.test/api/v2/tasks/",
    ]
