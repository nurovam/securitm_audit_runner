from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from securitm_audit_agent import __version__
from securitm_audit_agent.checks import register_builtin_checks
from securitm_audit_agent.config import load_config
from securitm_audit_agent.core import AuditRunner, CheckRegistry, Status
from securitm_audit_agent.integrations import SecurITMClient
from securitm_audit_agent.platform import AuditContext


def _get_nested(config: Mapping[str, Any], path: list[str], default: Any) -> Any:
    current: Any = config
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def _render_fields(fields: Dict[str, Any], values: Dict[str, Any]) -> Dict[str, Any]:
    rendered: Dict[str, Any] = {}
    for key, value in fields.items():
        if isinstance(value, str):
            rendered[key] = value.format_map(values)
        else:
            rendered[key] = value
    return rendered


def _build_task_payload(
    result,
    tasks_cfg: Mapping[str, Any],
    host: Mapping[str, Any],
    asset_uuid: Optional[str],
) -> Dict[str, Any]:
    author_name = tasks_cfg.get("author_name", "audit_agent")
    desc_template = tasks_cfg.get(
        "desc_template",
        "Author: {author}\\nHost: {hostname}\\nCheck: {check_id}\\nStatus: {status}",
    )
    name_template = tasks_cfg.get("name_template", "[{status}] {check_id}")
    desc_max_length = int(tasks_cfg.get("desc_max_length", 5000))

    values = {
        "author": author_name,
        "hostname": host.get("hostname") or "",
        "fqdn": host.get("fqdn") or "",
        "ip": host.get("ip") or "",
        "check_id": result.check_id,
        "status": result.status.value,
        "message": result.message,
        "evidence": result.evidence or "",
        "remediation": result.remediation,
        "severity": result.severity,
    }

    name = name_template.format_map(values)
    desc = desc_template.format_map(values)
    if len(desc) > desc_max_length:
        desc = desc[:desc_max_length]

    payload: Dict[str, Any] = {
        "name": name,
        "desc": desc,
        "is_done": 0,
    }

    author_uuid = tasks_cfg.get("author_uuid") or None
    responsible_uuid = tasks_cfg.get("responsible_uuid") or None
    priority = tasks_cfg.get("priority")
    deadline_days = tasks_cfg.get("deadline_days")

    if author_uuid:
        payload["author_uuid"] = author_uuid
    if responsible_uuid:
        payload["responsible_uuid"] = responsible_uuid
    if priority is not None:
        payload["priority"] = int(priority)
    if deadline_days:
        deadline = date.today() + timedelta(days=int(deadline_days))
        payload["deadline_at"] = deadline.strftime("%d.%m.%Y")
    if asset_uuid:
        payload["assets"] = [asset_uuid]

    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux audit runner (core)")
    parser.add_argument("-c", "--config", default="configs/audit.yml")
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--no-api", action="store_true", help="Disable SecurITM API integration")
    parser.add_argument("--dry-run", action="store_true", help="Print planned checks and exit")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    args = parser.parse_args()

    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")

    config = load_config(args.config)

    registry = CheckRegistry()
    register_builtin_checks(registry)

    enabled_checks = _get_nested(config, ["audit", "checks", "enabled"], None)
    params = _get_nested(config, ["audit", "params"], {})

    if args.dry_run:
        plan = enabled_checks or list(registry.ids())
        print("Planned checks:")
        for check_id in plan:
            print(f"- {check_id}")
        return

    ctx = AuditContext(agent_version=__version__)
    runner = AuditRunner(registry)
    report = runner.run(ctx, enabled_checks, params)

    output_path = args.output or _get_nested(config, ["audit", "output", "json"], None)
    if output_path:
        Path(output_path).write_text(
            json.dumps(report.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logging.info("Report saved to %s", output_path)

    if args.no_api:
        return

    securitm_cfg = _get_nested(config, ["securitm"], {})
    if not securitm_cfg or not securitm_cfg.get("enabled", False):
        return

    token_env = securitm_cfg.get("token_env")
    if not token_env:
        logging.error("securitm.token_env is not set")
        sys.exit(2)
    token = os.getenv(token_env)
    if not token:
        logging.error("Missing token in environment: %s", token_env)
        sys.exit(2)

    base_url = securitm_cfg.get("base_url", "").strip()
    if not base_url:
        logging.error("securitm.base_url is not set")
        sys.exit(2)

    verify_ssl = bool(securitm_cfg.get("verify_ssl", True))
    client = SecurITMClient(base_url=base_url, token=token, verify_ssl=verify_ssl)

    assets_cfg = securitm_cfg.get("assets", {})
    asset_type_slug = assets_cfg.get("asset_type_slug")
    import_template = assets_cfg.get("import_template")
    name_field = assets_cfg.get("name_field", "name")
    import_name_field = assets_cfg.get("import_name_field")
    import_fields = assets_cfg.get("import_fields", {})

    if not asset_type_slug or not import_template:
        logging.error("securitm.assets.asset_type_slug or import_template is missing")
        sys.exit(2)

    if not isinstance(import_fields, Mapping):
        logging.error("securitm.assets.import_fields must be a mapping")
        sys.exit(2)

    values = {
        "hostname": ctx.host_facts.get("hostname"),
        "fqdn": ctx.host_facts.get("fqdn"),
        "ip": ctx.host_facts.get("ip") or "",
    }
    rendered_fields = _render_fields(import_fields, values)

    if import_name_field:
        asset_name = str(rendered_fields.get(import_name_field, ""))
    else:
        asset_name = str(rendered_fields.get("name") or rendered_fields.get("Название") or "")
    if not asset_name:
        logging.error("Asset name is missing; set securitm.assets.import_name_field")
        sys.exit(2)

    asset = client.ensure_asset(
        asset_type_slug=asset_type_slug,
        name_field=name_field,
        template=import_template,
        import_fields=rendered_fields,
        asset_name=asset_name,
    )
    asset_uuid = asset.get("uuid")

    tasks_cfg = securitm_cfg.get("tasks", {})
    if not tasks_cfg.get("enabled", True):
        return

    for result in report.results:
        if result.status != Status.FAIL:
            continue
        payload = _build_task_payload(result, tasks_cfg, ctx.host_facts, asset_uuid)
        client.create_task(payload)
        logging.info("Created task for %s", result.check_id)


if __name__ == "__main__":
    main()
