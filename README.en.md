# SecurITM Audit Agent

Local CLI tool for auditing a Linux host with a plugin system, JSON/PDF reports,
and SecurITM integration.

## Current Status

The project already supports:
- local Linux security checks;
- JSON report generation;
- optional PDF report generation;
- host asset lookup/creation in SecurITM;
- task creation attempts in SecurITM for `FAIL` results.

Important caveats:
- the working config is **not** tracked in Git;
- the repository only ships `configs/audit.yml.example`;
- SecurITM task creation is currently the least reliable part of the project because it depends on real cloud API behavior.

## First Run

Create your local working config first:

```bash
cp configs/audit.yml.example configs/audit.yml
```

Then fill in:
- SecurITM settings;
- asset type;
- import template;
- `author_uuid` / `responsible_uuid` if needed.

Without this step the CLI default path will fail, because it still expects `configs/audit.yml`.

## Quick Start From the Repository

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp configs/audit.yml.example configs/audit.yml
python -m securitm_audit_agent -c configs/audit.yml --dry-run
python -m securitm_audit_agent -c configs/audit.yml -o audit-report.json
```

## Package Installation

Minimal install without PDF:

```bash
pip install .
```

Install with PDF support:

```bash
pip install ".[pdf]"
```

Install for development:

```bash
pip install ".[dev]"
```

CLI entrypoint after install:

```bash
securitm-audit -c configs/audit.yml --dry-run
```

## Usage

```bash
python -m securitm_audit_agent -c configs/audit.yml -o audit-report.json
securitm-audit -c configs/audit.yml -o audit-report.json
```

Disable API integration:

```bash
python -m securitm_audit_agent -c configs/audit.yml --no-api
```

Dry-run:

```bash
python -m securitm_audit_agent -c configs/audit.yml --dry-run
```

## CLI Flags

- `-c`, `--config` — YAML/JSON config path. Default: `configs/audit.yml`.
- `-o`, `--output` — JSON report path. Overrides `audit.output.json`.
- `--no-api` — disable SecurITM integration.
- `--dry-run` — print the execution plan and exit.
- `-v`, `--verbose` — logging verbosity. Supports `-v` and `-vv`.

## Configuration

Tracked template:

```text
configs/audit.yml.example
```

Local working file:

```text
configs/audit.yml
```

The working file is Git-ignored on purpose.

Key config blocks:
- `audit.checks.builtin`
- `audit.checks.enabled`
- `audit.plugins`
- `audit.params`
- `audit.output.json`
- `audit.output.pdf`
- `audit.output.pdf_font_path`

## PDF

PDF export is enabled through `audit.output.pdf`.

For Cyrillic text you need a TTF font with Cyrillic support, for example:

```text
/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
```

If `reportlab` or the configured font is unavailable, JSON output will still be produced and the PDF failure will only be logged.

## Plugins

The repository currently ships a baseline plugin:

```text
securitm_audit_agent.plugins.met_rekom_linux
```

It implements a baseline set of Linux hardening checks.
Some requirements are still manual-only and return `SKIP`.
See `docs/MANUAL_CHECKS.md`.

## SecurITM Integration

To enable API integration:

1. Set `securitm.enabled: true` in `configs/audit.yml`.
2. Export your token:

```bash
export SECURITM_TOKEN="YOUR_TOKEN"
```

Important config keys:
- `securitm.base_url`
- `securitm.token_env`
- `securitm.assets.asset_type_slug`
- `securitm.assets.import_template`
- `securitm.assets.import_fields`
- `securitm.tasks.author_uuid`
- `securitm.tasks.responsible_uuid`

## Known Limitations

- The CLI still expects a prepared `configs/audit.yml` by default.
- SecurITM task creation is not fully reliable yet because the cloud API behavior does not always match the public documentation.
- Some baseline checks are intentionally manual and return `SKIP`.
- Some baseline checks may be noisy on system accounts and system-owned paths.

## Project Docs

- Main Russian README: `README.md`
- Backlog: `docs/BACKLOG.md`
- Contributing: `CONTRIBUTING.md`
- Manual checks policy: `docs/MANUAL_CHECKS.md`
- Changelog: `CHANGELOG.md`
