from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    if config_path.suffix in {".yml", ".yaml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML configs")
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    if config_path.suffix == ".json":
        return json.loads(config_path.read_text(encoding="utf-8"))

    raise ValueError("Unsupported config format; use .yml, .yaml, or .json")
