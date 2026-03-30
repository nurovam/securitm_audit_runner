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
