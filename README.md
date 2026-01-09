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

## Интеграция с SecurITM

Для включения интеграции:

1) В `configs/audit.yml` установите `securitm.enabled: true`.
2) Задайте токен в окружении:

```bash
export SECURITM_TOKEN="ВАШ_ТОКЕН"
```

Основные поля конфигурации:

- `securitm.base_url` — адрес сервиса (для облака `https://service.securitm.ru`).
- `securitm.token_env` — имя переменной окружения с токеном.
- `securitm.assets.asset_type_slug` — тип актива из URL реестра.
- `securitm.assets.import_template` — имя шаблона импорта активов.
- `securitm.assets.import_fields` — поля импорта (используйте `{hostname}`, `{fqdn}`, `{ip}`).
- `securitm.tasks.author_uuid` — UUID автора задачи (опционально).
