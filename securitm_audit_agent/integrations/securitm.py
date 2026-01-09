from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional

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
        url = f"{self.base_url}/api/v1/assets/get/{asset_type_slug}"
        if fields:
            url = f"{url}?{'&'.join(fields)}"
        response = self.session.get(url, verify=self.verify_ssl, timeout=self.timeout)
        self._raise_for_status(response)
        payload = response.json()
        return payload.get("data", [])

    def find_asset_by_name(
        self,
        asset_type_slug: str,
        name: str,
        name_field: str = "name",
    ) -> Optional[Dict[str, Any]]:
        assets = self.get_assets(asset_type_slug)
        for asset in assets:
            candidate = asset.get(name_field) or asset.get("name")
            if not isinstance(candidate, str):
                continue
            if candidate.strip().lower() == name.strip().lower():
                return asset
        return None

    def import_assets(self, template: str, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        asset = self.find_asset_by_name(asset_type_slug, name, name_field=name_field)
        if asset:
            return asset
        raise RuntimeError("Asset import did not return a visible asset")

    def create_task(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base_url}/api/v2/tasks"
        response = self.session.post(url, json=payload, verify=self.verify_ssl, timeout=self.timeout)
        self._raise_for_status(response)
        return response.json() if response.content else {}

    def _raise_for_status(self, response: requests.Response) -> None:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
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
