# Клиент для API SecurITM (активы и задачи).
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests


class SecurITMClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True, timeout: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )

    def get_assets(self, asset_type_slug: str, fields: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
        # API выгрузки активов по типу (slug).
        url = f"{self.base_url}/api/v1/assets/get/{asset_type_slug}"
        if fields:
            url = f"{url}?{'&'.join(fields)}"
        response = self.session.get(url, verify=self.verify_ssl, timeout=self.timeout)
        self._raise_for_status(response)
        payload = response.json()
        return self._extract_items(payload)

    def find_asset_by_name(
        self,
        asset_type_slug: str,
        name: str,
        name_field: str = "name",
    ) -> Optional[Dict[str, Any]]:
        requested_fields = ["uuid", "name"]
        if name_field not in requested_fields:
            requested_fields.append(name_field)

        assets = self.get_assets(asset_type_slug, fields=requested_fields)
        for asset in assets:
            candidate = asset.get(name_field) or asset.get("name")
            if not isinstance(candidate, str):
                continue
            if candidate.strip().lower() == name.strip().lower():
                return asset
        return None

    def import_assets(self, template: str, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Импорт активов через шаблон SecurITM.
        url = f"{self.base_url}/api/v1/assets/import"
        payload = {
            "template": template,
            "assets": assets,
        }
        response = self.session.post(url, json=payload, verify=self.verify_ssl, timeout=self.timeout)
        self._raise_for_status(response)
        return response.json() if response.content else {}

    def ensure_asset(
        self,
        asset_type_slug: str,
        name_field: str,
        template: str,
        import_fields: Dict[str, Any],
        asset_name: str,
    ) -> Dict[str, Any]:
        name = asset_name.strip()
        if not name:
            raise ValueError("Asset name is missing")

        asset = self.find_asset_by_name(asset_type_slug, name, name_field=name_field)
        if asset:
            return asset

        self.import_assets(template, [import_fields])
        # Повторный поиск после импорта.
        asset = self.find_asset_by_name(asset_type_slug, name, name_field=name_field)
        if asset:
            return asset
        raise RuntimeError("Asset import did not return a visible asset")

    def create_task(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/tasks"
        response = self.session.post(
            url,
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
            allow_redirects=False,
        )
        if getattr(response, "is_redirect", False) or getattr(response, "is_permanent_redirect", False):
            location = response.headers.get("Location")
            if not location:
                raise RuntimeError("Task creation endpoint redirected without Location header")
            redirect_url = urljoin(url, location)
            response = self.session.post(
                redirect_url,
                json=payload,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=False,
            )
        self._raise_for_status(response)
        data = response.json() if response.content else {}
        created = self._extract_first_item(data)
        if created:
            return created
        if isinstance(data, dict) and any(key in data for key in ("uuid", "id", "name")):
            return data
        status_code = getattr(response, "status_code", "unknown")
        response_url = getattr(response, "url", url)
        raise RuntimeError(
            "Task creation returned no task object: "
            f"status={status_code}, url={response_url}, body={json.dumps(data, ensure_ascii=False)}"
        )

    def get_tasks(
        self,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        per_page: int = 100,
    ) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/v2/tasks"
        params: Dict[str, Any] = {
            "page": page,
            "perPage": per_page,
        }
        if filters:
            params["filters"] = json.dumps(filters, ensure_ascii=False)
        response = self.session.get(url, params=params, verify=self.verify_ssl, timeout=self.timeout)
        self._raise_for_status(response)
        payload = response.json()
        return self._extract_items(payload)

    def find_open_task(self, name: str, asset_uuid: Optional[str] = None) -> Optional[Dict[str, Any]]:
        filters: Dict[str, Any] = {
            "fields": [
                {"name": name, "op": "eq"},
                {"is_done": 0, "op": "eq"},
            ]
        }
        if asset_uuid:
            filters["relations"] = [
                {"assets.uuid": asset_uuid, "op": "eq"},
            ]

        tasks = self.get_tasks(filters=filters)
        for task in tasks:
            if task.get("name") != name:
                continue
            if asset_uuid:
                assets = task.get("assets") or []
                if not isinstance(assets, list):
                    continue
                linked_uuids = {asset.get("uuid") for asset in assets if isinstance(asset, dict)}
                if asset_uuid not in linked_uuids:
                    continue
            return task
        return None

    def create_task_if_missing(self, payload: Dict[str, Any]) -> tuple[Dict[str, Any], bool]:
        name = str(payload.get("name") or "").strip()
        assets = payload.get("assets") or []
        asset_uuid = assets[0] if isinstance(assets, list) and assets else None

        if name:
            try:
                existing = self.find_open_task(name, asset_uuid=asset_uuid)
            except requests.RequestException:
                # Проверка на дубль — вспомогательный шаг.
                # Если API не даёт список задач или не принимает фильтры,
                # всё равно пытаемся создать задачу, чтобы не терять FAIL.
                existing = None
            else:
                if existing:
                    return existing, False

        created = self.create_task(payload)
        return created, True

    def _extract_items(self, payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []

        data = payload.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            data_objects = data.get("objects")
            if isinstance(data_objects, list):
                return [item for item in data_objects if isinstance(item, dict)]

        nested_items = payload.get("items")
        if isinstance(nested_items, list):
            return [item for item in nested_items if isinstance(item, dict)]

        objects = payload.get("objects")
        if isinstance(objects, list):
            return [item for item in objects if isinstance(item, dict)]

        return []

    def _extract_first_item(self, payload: Any) -> Optional[Dict[str, Any]]:
        items = self._extract_items(payload)
        if items:
            return items[0]
        return None

    def _raise_for_status(self, response: requests.Response) -> None:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            # Добавляем тело ответа для диагностики ошибок API.
            body = ""
            try:
                payload = response.json()
                body = json.dumps(payload, ensure_ascii=False)
            except ValueError:
                body = response.text or ""
            if len(body) > 2000:
                body = body[:2000] + "...(truncated)"
            message = f"{exc} | response body: {body}"
            raise requests.HTTPError(message, response=response) from None
