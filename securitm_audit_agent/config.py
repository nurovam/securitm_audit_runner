# Загрузка конфигурации из YAML/JSON файлов.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def resolve_config_path(path: str | Path) -> Tuple[Path, bool]:
    """Возвращает путь к рабочему конфигу или к шаблону .example.

    Если основной файл отсутствует, но рядом лежит шаблон `*.example`,
    используем его как безопасный read-only fallback для первого запуска.
    """
    config_path = Path(path)
    if config_path.exists():
        return config_path, False

    example_path = config_path.with_name(config_path.name + ".example")
    if example_path.exists():
        return example_path, True

    raise FileNotFoundError(
        f"Config not found: {config_path}. Expected either {config_path} "
        f"or template {example_path}."
    )


def load_config(path: str | Path) -> Dict[str, Any]:
    config_path = Path(path)
    suffixes = config_path.suffixes
    if suffixes[-2:] in ([".yml", ".example"], [".yaml", ".example"]):
        config_format = ".yml"
    elif suffixes[-2:] == [".json", ".example"]:
        config_format = ".json"
    else:
        config_format = config_path.suffix

    # Формат определяем по расширению файла.
    if config_format in {".yml", ".yaml"}:
        if yaml is None:
            raise RuntimeError("PyYAML is required for YAML configs")
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    if config_format == ".json":
        return json.loads(config_path.read_text(encoding="utf-8"))

    raise ValueError("Unsupported config format; use .yml, .yaml, or .json")
