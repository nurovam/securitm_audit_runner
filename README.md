# SecurITM Audit Runner

Базовое ядро Linux‑агента аудита с последующей интеграцией в SecurITM.
На этом этапе реализованы доменная модель, контекст платформы, встроенные проверки и минимальный CLI.

## Объём работ (этап 1)

- Доменная модель: проверки, результаты, отчёт.
- Платформенный контекст (факты хоста + безопасные адаптеры).
- Встроенные проверки и CLI с JSON‑отчётом.

## Быстрый старт

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m securitm_audit_agent -c configs/audit.yml -o audit-report.json
```

## Следующие шаги

- Система плагинов.
- Интеграция с API SecurITM.
