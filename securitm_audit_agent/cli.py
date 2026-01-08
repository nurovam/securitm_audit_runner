from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Mapping

from securitm_audit_agent import __version__
from securitm_audit_agent.checks import register_builtin_checks
from securitm_audit_agent.config import load_config
from securitm_audit_agent.core import AuditRunner, CheckRegistry
from securitm_audit_agent.platform import AuditContext


def _get_nested(config: Mapping[str, Any], path: list[str], default: Any) -> Any:
    current: Any = config
    for key in path:
        if not isinstance(current, Mapping) or key not in current:
            return default
        current = current[key]
    return current


def main() -> None:
    parser = argparse.ArgumentParser(description="Linux audit runner (core)")
    parser.add_argument("-c", "--config", default="configs/audit.yml")
    parser.add_argument("-o", "--output", default=None)
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


if __name__ == "__main__":
    main()
