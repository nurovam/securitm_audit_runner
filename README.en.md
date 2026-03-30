# SecurITM Audit Agent

Modular Linux security audit agent with SecurITM integration.

## What It Does

- Runs local security checks on a Linux host.
- Produces a machine-readable JSON report.
- Optionally produces a human-readable PDF report.
- Syncs the host as an asset in SecurITM.
- Creates tasks in SecurITM for failed checks.

## Installation

Minimal install:

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

## Usage

```bash
securitm-audit -c configs/audit.yml --dry-run
securitm-audit -c configs/audit.yml -o audit-report.json
```

## Project Docs

- Main README: `README.md`
- Backlog: `docs/BACKLOG.md`
- Contributing: `CONTRIBUTING.md`
- Manual checks policy: `docs/MANUAL_CHECKS.md`
- Changelog: `CHANGELOG.md`
