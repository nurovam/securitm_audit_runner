# Клиент для API SecurITM (активы и задачи).
from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import requests


class SecurITMClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True, timeout: int = 30) -> None:
        self.logger = logging.getLogger(__name__)
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
        self.logger.debug("SecurITM GET assets url=%s", url)
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
        self.logger.debug("SecurITM POST assets/import payload=%s", self._short_json(payload))
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
        # В облаке создание задач идёт через отдельный endpoint /create.
        url = f"{self.base_url}/api/v2/tasks/create"
        self.logger.debug("SecurITM POST tasks payload=%s", self._short_json(payload))
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
            self.logger.debug("SecurITM POST tasks redirect location=%s", redirect_url)
            response = self.session.post(
                redirect_url,
                json=payload,
                verify=self.verify_ssl,
                timeout=self.timeout,
                allow_redirects=False,
            )
        self.logger.debug(
            "SecurITM POST tasks response status=%s url=%s content_type=%s body=%s",
            getattr(response, "status_code", "unknown"),
            getattr(response, "url", url),
            response.headers.get("Content-Type") if getattr(response, "headers", None) else None,
            self._short_text(getattr(response, "text", "")),
        )
        self._raise_for_status(response)
        return response.json() if response.content else {}

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
        self.logger.debug("SecurITM GET tasks params=%s", self._short_json(params))
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

        try:
            tasks = self.get_tasks(filters=filters)
        except requests.RequestException as exc:
            self.logger.debug("SecurITM filtered task lookup failed, fallback to unfiltered scan: %s", exc)
        else:
            for task in tasks:
                if self._task_matches(task, name, asset_uuid):
                    return task

        for page in range(1, 4):
            tasks = self.get_tasks(page=page, per_page=100)
            for task in tasks:
                if self._task_matches(task, name, asset_uuid):
                    return task
            if len(tasks) < 100:
                break
        return None

    def create_task_if_missing(self, payload: Dict[str, Any]) -> tuple[Dict[str, Any], bool]:
        name = str(payload.get("name") or "").strip()
        assets = payload.get("assets") or []
        asset_uuid = assets[0] if isinstance(assets, list) and assets else None

        if name:
            try:
                existing = self.find_open_task(name, asset_uuid=asset_uuid)
            except requests.RequestException as exc:
                self.logger.debug("SecurITM pre-create task lookup failed: %s", exc)
            else:
                if existing:
                    return existing, False

        created = self.create_task(payload)
        if created:
            return created, True

        if not name:
            raise RuntimeError("Task creation returned no task object and task name is empty")

        # Поведение ближе к ранней версии: POST считается основным действием.
        # Если API не вернул объект задачи, пробуем коротко подтвердить её создание через GET.
        last_error: Optional[Exception] = None
        for attempt in range(3):
            try:
                existing = self.find_open_task(name, asset_uuid=asset_uuid)
            except requests.RequestException as exc:
                last_error = exc
                self.logger.debug(
                    "SecurITM task verification attempt=%s name=%s asset_uuid=%s failed: %s",
                    attempt + 1,
                    name,
                    asset_uuid,
                    exc,
                )
            else:
                if existing:
                    return existing, True
            if attempt < 2:
                time.sleep(1.0)

        if last_error is not None:
            raise RuntimeError(
                "Task creation returned no task object and verification failed: "
                f"name={name}, asset_uuid={asset_uuid}, last_error={last_error}"
            ) from last_error
        raise RuntimeError(
            "Task creation returned no task object and task is still absent after verification: "
            f"name={name}, asset_uuid={asset_uuid}"
        )

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

    def _extract_task_object(self, payload: Any) -> Optional[Dict[str, Any]]:
        if isinstance(payload, dict):
            if any(key in payload for key in ("uuid", "id", "name")):
                return payload
            data = payload.get("data")
            if isinstance(data, dict) and not isinstance(data.get("objects"), list):
                if any(key in data for key in ("uuid", "id", "name")):
                    return data
        return None

    def _task_matches(self, task: Dict[str, Any], name: str, asset_uuid: Optional[str]) -> bool:
        if task.get("name") != name:
            return False
        is_done = task.get("is_done")
        if is_done not in (0, False, None):
            return False
        if not asset_uuid:
            return True

        assets = task.get("assets") or []
        if not isinstance(assets, list):
            return False
        linked_uuids = {asset.get("uuid") for asset in assets if isinstance(asset, dict)}
        return asset_uuid in linked_uuids

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
            request = getattr(response, "request", None)
            method = getattr(request, "method", "unknown")
            url = getattr(response, "url", "unknown")
            message = f"{method} {url} -> {exc} | response body: {body}"
            raise requests.HTTPError(message, response=response) from None

    def _short_json(self, payload: Any, limit: int = 600) -> str:
        text = json.dumps(payload, ensure_ascii=False)
        return self._short_text(text, limit=limit)

    def _short_text(self, text: str, limit: int = 600) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "...(truncated)"
