# Тесты загрузки конфига и fallback на шаблон .example.
from __future__ import annotations

from pathlib import Path

from securitm_audit_agent.config import load_config, resolve_config_path


def test_resolve_config_path_falls_back_to_example(tmp_path) -> None:
    example_path = tmp_path / "audit.yml.example"
    example_path.write_text("audit:\n  checks:\n    builtin: true\n", encoding="utf-8")

    resolved_path, used_example = resolve_config_path(tmp_path / "audit.yml")

    assert used_example is True
    assert resolved_path == example_path
    assert load_config(resolved_path)["audit"]["checks"]["builtin"] is True


def test_resolve_config_path_prefers_real_config_over_example(tmp_path) -> None:
    config_path = tmp_path / "audit.yml"
    example_path = tmp_path / "audit.yml.example"
    config_path.write_text("audit:\n  output:\n    json: report.json\n", encoding="utf-8")
    example_path.write_text("audit:\n  output:\n    json: example.json\n", encoding="utf-8")

    resolved_path, used_example = resolve_config_path(config_path)

    assert used_example is False
    assert resolved_path == config_path
    assert load_config(resolved_path)["audit"]["output"]["json"] == "report.json"


def test_example_config_excludes_manual_only_checks_by_default() -> None:
    config = load_config(Path(__file__).resolve().parents[1] / "configs" / "audit.yml.example")
    enabled = set(config["audit"]["checks"]["enabled"])

    assert "met_2_3_2_running_process_file_perms" not in enabled
    assert "met_2_3_3_cron_jobs_file_perms" not in enabled
    assert "met_2_3_4_sudo_exec_file_perms" not in enabled
    assert "met_2_3_8_system_bins_libs_perms" not in enabled
