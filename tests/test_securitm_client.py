# Тесты клиента SecurITM, связанные с идемпотентностью задач.
from __future__ import annotations

import requests

from securitm_audit_agent.integrations.securitm import SecurITMClient


def test_create_task_if_missing_returns_created_marker_when_response_empty(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    monkeypatch.setattr(client, "create_task", lambda task_payload: {})
    monkeypatch.setattr(client, "find_open_task", lambda name, host_name=None: None)

    task, created = client.create_task_if_missing(payload)

    assert created is True
    assert task == {"name": payload["name"]}


def test_create_task_if_missing_returns_created_task_object(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    monkeypatch.setattr(client, "create_task", lambda task_payload: {"uuid": "task-created"})
    monkeypatch.setattr(client, "find_open_task", lambda name, host_name=None: None)

    task, created = client.create_task_if_missing(payload)

    assert created is True
    assert task["uuid"] == "task-created"


def test_create_task_if_missing_returns_created_marker_when_post_returns_task_list(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    monkeypatch.setattr(
        client,
        "create_task",
        lambda task_payload: {
            "data": {
                "total": 1,
                "objects": [{"uuid": "task-old", "name": "Old task"}],
            }
        },
    )
    monkeypatch.setattr(client, "find_open_task", lambda name, host_name=None: None)

    task, created = client.create_task_if_missing(payload)

    assert created is True
    assert task == {"name": payload["name"]}


def test_create_task_if_missing_returns_existing_task_before_post(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    monkeypatch.setattr(
        client,
        "find_open_task",
        lambda name, host_name=None: {"uuid": "task-existing", "name": name, "is_done": False},
    )
    monkeypatch.setattr(client, "create_task", lambda task_payload: {"uuid": "task-created"})

    task, created = client.create_task_if_missing(payload)

    assert created is False
    assert task["uuid"] == "task-existing"


def test_find_open_task_accepts_filtered_result_and_matches_host_from_desc(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    calls = []

    def _get_tasks(filters=None, page=1, per_page=100):
        calls.append({"filters": filters, "page": page, "per_page": per_page})
        if filters is not None:
            return [
                {
                    "uuid": "task-existing",
                    "name": "[FAIL] check",
                    "is_done": False,
                    "desc": "Author: audit_agent\nHost: kalipurple\nStatus: FAIL",
                }
            ]
        return []

    monkeypatch.setattr(client, "get_tasks", _get_tasks)

    task = client.find_open_task("[FAIL] check", host_name="kalipurple")

    assert task is not None
    assert task["uuid"] == "task-existing"
    assert calls[0]["filters"]["fields"] == [
        {"name": "FAIL check", "op": "eq"},
        {"is_done": 0, "op": "eq"},
    ]
    assert calls[0]["per_page"] == 100
    assert len(calls) == 1


def test_find_open_task_uses_name_and_status_filters_without_asset(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    calls = []

    def _get_tasks(filters=None, page=1, per_page=100):
        calls.append({"filters": filters, "page": page, "per_page": per_page})
        return [{"uuid": "task-existing", "name": "[FAIL] check", "is_done": False}]

    monkeypatch.setattr(client, "get_tasks", _get_tasks)

    task = client.find_open_task("[FAIL] check", host_name=None)

    assert task is not None
    assert task["uuid"] == "task-existing"
    assert calls[0]["filters"]["fields"] == [
        {"name": "FAIL check", "op": "eq"},
        {"is_done": 0, "op": "eq"},
    ]
    assert calls[0]["per_page"] == 100
    assert len(calls) == 1


def test_task_match_normalizes_bracketed_status_prefix() -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    task = {
        "uuid": "task-existing",
        "name": "FAIL met_2_1_2_ssh_root_login",
        "is_done": False,
    }

    assert client._task_matches(task, "[FAIL] met_2_1_2_ssh_root_login") is True


def test_task_match_requires_same_host_when_host_is_present() -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    task = {
        "uuid": "task-existing",
        "name": "FAIL met_2_1_2_ssh_root_login",
        "is_done": False,
        "desc": "Author: audit_agent\nHost: other-host\nStatus: FAIL",
    }

    assert client._task_matches(task, "[FAIL] met_2_1_2_ssh_root_login", host_name="kalipurple") is False


def test_extract_host_from_desc_parses_host_line() -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    host = client._extract_host_from_desc("Author: audit_agent\nHost: KaliPurple\nStatus: FAIL")

    assert host == "kalipurple"


def test_create_task_if_missing_raises_when_precheck_lookup_fails(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")
    payload = {
        "name": "[FAIL] check",
        "assets": ["asset-uuid"],
    }

    response = requests.Response()
    response.status_code = 422

    def _raise_bad_request(name, host_name=None):
        raise requests.HTTPError("unprocessable", response=response)

    monkeypatch.setattr(client, "find_open_task", _raise_bad_request)
    monkeypatch.setattr(client, "create_task", lambda task_payload: {"uuid": "task-created"})

    try:
        client.create_task_if_missing(payload)
    except requests.HTTPError as exc:
        assert "unprocessable" in str(exc)
    else:
        raise AssertionError("HTTPError was not raised")


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


def test_create_task_returns_raw_payload_when_response_has_no_task_object(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    class _Response:
        content = b"1"

        def json(self):
            return {"ok": True}

    monkeypatch.setattr(client.session, "post", lambda *args, **kwargs: _Response())
    monkeypatch.setattr(client, "_raise_for_status", lambda response: None)

    created = client.create_task({"name": "Task 1", "is_done": 0})

    assert created == {"ok": True}


def test_create_task_returns_task_list_response_as_is(monkeypatch) -> None:
    client = SecurITMClient(base_url="https://example.test", token="token")

    class _Response:
        content = b"1"
        is_redirect = False
        is_permanent_redirect = False
        headers = {}
        status_code = 200
        url = "https://example.test/api/v2/tasks"
        text = '{"data":{"total":1,"objects":[{"uuid":"task-old","name":"Old task"}]}}'

        def json(self):
            return {
                "data": {
                    "total": 1,
                    "objects": [{"uuid": "task-old", "name": "Old task"}],
                }
            }

    monkeypatch.setattr(client.session, "post", lambda *args, **kwargs: _Response())
    monkeypatch.setattr(client, "_raise_for_status", lambda response: None)

    created = client.create_task({"name": "Task 1", "is_done": 0})

    assert created == {
        "data": {
            "total": 1,
            "objects": [{"uuid": "task-old", "name": "Old task"}],
        }
    }


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
        "https://example.test/api/v2/tasks/create",
        "https://example.test/api/v2/tasks/",
    ]
