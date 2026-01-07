# SecurITM Audit Runner

Foundational core for a Linux audit agent that will integrate with SecurITM.
This first stage delivers the domain model and execution core (checks, registry, runner, report).

## Scope (phase 1)

- Core domain objects: checks, results, report.
- Check registry and runner.
- Minimal package layout, ready for further development.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Next steps

- Add platform context (host facts, safe OS adapters).
- Add built-in checks and plugin system.
- Add CLI, config loader, and SecurITM API integration.
