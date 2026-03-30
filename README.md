# SecurITM Audit Agent

Базовое ядро Linux‑агента аудита с последующей интеграцией в SecurITM.
На этом этапе реализованы доменная модель, контекст платформы, встроенные проверки и минимальный CLI.

## Управление Проектом

- План исправлений и технического долга: `docs/BACKLOG.md`
- Правила работы с репозиторием: `CONTRIBUTING.md`
- Changelog: `CHANGELOG.md`
- English README: `README.en.md`
- Политика ручных проверок: `docs/MANUAL_CHECKS.md`

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

## Установка Пакета

Минимальная установка без PDF:

```bash
pip install .
```

Установка с поддержкой PDF:

```bash
pip install ".[pdf]"
```

Установка для разработки и запуска тестов:

```bash
pip install ".[dev]"
```

После установки CLI доступен как команда:

```bash
securitm-audit -c configs/audit.yml --dry-run
```

PDF-отчет настраивается через `audit.output.pdf` в конфиге.
Для русских символов нужен TTF-шрифт с поддержкой кириллицы. Укажите путь
в `audit.output.pdf_font_path` (например,
`/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf`).

## Использование

Базовый запуск:

```bash
python -m securitm_audit_agent -c configs/audit.yml -o audit-report.json
# или после установки пакета
securitm-audit -c configs/audit.yml -o audit-report.json
```

Запуск без интеграции с API:

```bash
python -m securitm_audit_agent -c configs/audit.yml --no-api
```

План проверок без выполнения:

```bash
python -m securitm_audit_agent -c configs/audit.yml --dry-run
```

### Все флаги CLI

- `-c`, `--config` — путь к конфигурации (YAML/JSON), по умолчанию `configs/audit.yml`.
- `-o`, `--output` — путь к JSON-отчету (переопределяет `audit.output.json`).
- `--no-api` — отключить интеграцию с SecurITM.
- `--dry-run` — вывести список проверок и выйти.
- `-v`, `--verbose` — уровень логирования (повторяемый флаг: `-v`, `-vv`).

## Тесты

Локальный запуск тестов:

```bash
pytest
```

### Конфигурация

Ключевые блоки:

- `audit.checks.builtin` — включить встроенные проверки.
- `audit.checks.enabled` — список активных проверок.
- `audit.plugins` — список модулей плагинов.
- `audit.params` — параметры для проверок.
- `audit.output.json` — путь к JSON-отчету.
- `audit.output.pdf` — путь к PDF-отчету.
- `audit.output.pdf_font_path` — путь к TTF-шрифту с кириллицей.

### Интеграция с SecurITM

Для API нужно:

1) Установить `securitm.enabled: true` в `configs/audit.yml`.
2) Экспортировать токен:

```bash
export SECURITM_TOKEN="ВАШ_ТОКЕН"
```

## Следующие шаги

- Новые плагины и проверки.
- Интеграция с API SecurITM.

## Плагины

В проект включен базовый плагин `securitm_audit_agent.plugins.met_rekom_linux`
с проверками по методическим рекомендациям ФСТЭК для Linux.
Часть пунктов требует ручной проверки и возвращает статус `SKIP`.
Подробности вынесены в `docs/MANUAL_CHECKS.md`.

Подключение плагинов выполняется через конфиг:

```yaml
audit:
  plugins:
    - "securitm_audit_agent.plugins.met_rekom_linux"
  checks:
    builtin: false
```

Каждый плагин должен экспортировать функцию `register(registry)`,
которая регистрирует проверки в реестре.

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
