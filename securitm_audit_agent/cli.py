# CLI для запуска аудита и интеграции с SecurITM.
"""
CLI entrypoint для запуска Linux-аудита.

Функции файла:
- Загружает конфиг (YAML/JSON) и нормализует параметры запуска.
- Собирает реестр проверок: встроенные + плагины (plugins.register(registry)).
- Формирует план проверок (enabled) и выполняет их через AuditRunner.
- Сохраняет отчёт (JSON и опционально PDF).
- Опционально интегрируется с SecurITM API:
  - создаёт/обновляет актив хоста (ensure_asset),
  - создаёт задачи по результатам FAIL.

Заметки по семантике статусов:
- FAIL  = контроль выполнен и НЕ соответствует требованиям → нужна задача.
- ERROR = ошибка исполнения проверки/агента → это не “несоответствие” (задачи обычно не создаём).
- SKIP  = пропущено (нет прав/не применимо/нужна ручная проверка).
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import sys
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

import requests

from securitm_audit_agent import __version__
from securitm_audit_agent.checks import register_builtin_checks
from securitm_audit_agent.config import load_config, resolve_config_path
from securitm_audit_agent.core import AuditRunner, CheckRegistry, Status
from securitm_audit_agent.platform import AuditContext


def _get_nested(config: Mapping[str, Any], path: list[str], default: Any) -> Any:
    """
    Безопасно достаёт вложенное значение из конфига по пути ключей.
    """
    current: Any = config
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def _render_fields(fields: Dict[str, Any], values: Dict[str, Any]) -> Dict[str, Any]:
    """Рендерит поля для импорт-шаблона SecurITM.

    Если значение поля — строка, применяем format_map(values),
    чтобы поддерживать шаблоны вида "{hostname}" / "{fqdn}" / "{ip}".
    Остальные типы (числа/булевы/вложенные структуры) оставляем как есть.
    """
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


def _load_plugins(registry: CheckRegistry, plugins: Any) -> None:
    if not plugins:
        return
    if not isinstance(plugins, list):
        raise ValueError("audit.plugins must be a list of module paths")
    for module_path in plugins:
        if not isinstance(module_path, str) or not module_path.strip():
            raise ValueError("audit.plugins entries must be non-empty strings")
        # Плагин должен экспортировать функцию register(registry).
        module = importlib.import_module(module_path)
        register = getattr(module, "register", None)
        if not callable(register):
            raise RuntimeError(f"Plugin {module_path} has no register(registry) function")
        register(registry)


def _sync_fail_tasks(
    client,
    report,
    tasks_cfg: Mapping[str, Any],
    host: Mapping[str, Any],
    asset_uuid: Optional[str],
) -> List[Dict[str, Any]]:
    """Создаёт или находит открытые задачи только для FAIL-результатов.

    Возвращает список задач, которые не удалось синхронизировать с API и которые
    можно сохранить в fallback-файл для ручной обработки.
    """
    unsynced: List[Dict[str, Any]] = []
    for result in report.results:
        if result.status != Status.FAIL:
            continue

        payload = _build_task_payload(result, tasks_cfg, host, asset_uuid)
        logging.debug("Task sync payload for %s: %s", result.check_id, json.dumps(payload, ensure_ascii=False))
        try:
            _task, created = client.create_task_if_missing(payload)
        except requests.HTTPError as exc:
            logging.error("Failed to sync task for %s: %s", result.check_id, exc)
            unsynced.append(
                {
                    "check_id": result.check_id,
                    "host": dict(host),
                    "payload": payload,
                    "error": str(exc),
                }
            )
            continue
        except (requests.RequestException, RuntimeError, ValueError) as exc:
            logging.error("Failed to sync task for %s: %s", result.check_id, exc)
            unsynced.append(
                {
                    "check_id": result.check_id,
                    "host": dict(host),
                    "payload": payload,
                    "error": str(exc),
                }
            )
            continue

        if created:
            logging.info("Created task for %s", result.check_id)
        else:
            logging.info("Open task already exists for %s", result.check_id)
    return unsynced


def _write_unsynced_tasks(path: str, tasks: List[Dict[str, Any]]) -> None:
    Path(path).write_text(
        json.dumps({"generated_at": date.today().isoformat(), "tasks": tasks}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


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

    try:
        config_path, used_example = resolve_config_path(args.config)
        config = load_config(config_path)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        logging.error("%s", exc)
        sys.exit(2)

    if used_example:
        logging.warning(
            "Config %s not found; using template %s. Copy the template to %s to customize local settings.",
            args.config,
            config_path,
            args.config,
        )

    registry = CheckRegistry()
    builtin_enabled = _get_nested(config, ["audit", "checks", "builtin"], True)
    if builtin_enabled:
        register_builtin_checks(registry)
    plugins = _get_nested(config, ["audit", "plugins"], [])
    try:
        _load_plugins(registry, plugins)
    except (ImportError, AttributeError, RuntimeError, TypeError, ValueError) as exc:
        logging.error("Failed to load plugins: %s", exc)
        sys.exit(2)

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

    pdf_output_path = _get_nested(config, ["audit", "output", "pdf"], None)
    pdf_font_path = _get_nested(config, ["audit", "output", "pdf_font_path"], None)
    if pdf_output_path:
        try:
            from securitm_audit_agent.reporting import write_pdf_report

            write_pdf_report(report, pdf_output_path, pdf_font_path)
        except (ImportError, FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            logging.error("PDF report failed: %s", exc)
        else:
            logging.info("PDF report saved to %s", pdf_output_path)

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
    from securitm_audit_agent.integrations import SecurITMClient

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

    try:
        asset = client.ensure_asset(
            asset_type_slug=asset_type_slug,
            name_field=name_field,
            template=import_template,
            import_fields=rendered_fields,
            asset_name=asset_name,
        )
    except (requests.RequestException, RuntimeError, ValueError) as exc:
        logging.error("Failed to sync asset with SecurITM: %s", exc)
        return
    asset_uuid = asset.get("uuid")

    tasks_cfg = securitm_cfg.get("tasks", {})
    if not tasks_cfg.get("enabled", True):
        return

    unsynced_tasks = _sync_fail_tasks(client, report, tasks_cfg, ctx.host_facts, asset_uuid)
    fallback_output_path = tasks_cfg.get("fallback_output_json")
    if unsynced_tasks and fallback_output_path:
        _write_unsynced_tasks(str(fallback_output_path), unsynced_tasks)
        logging.warning("Unsynced task payloads saved to %s", fallback_output_path)


if __name__ == "__main__":
    main()
