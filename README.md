# SecurITM Audit Runner

Foundational core for a Linux audit agent that will integrate with SecurITM.
This stage delivers the domain model, platform context, built-in checks, and a minimal CLI.

## Scope (phase 1)

- Core domain objects: checks, results, report.
- Platform context (host facts + safe adapters).
- Built-in checks and a minimal CLI with JSON output.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m securitm_audit_agent -c configs/audit.yml -o audit-report.json
```

## Next steps

- Add plugin system.
- Add SecurITM API integration.
