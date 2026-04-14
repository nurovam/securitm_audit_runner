# SecurITM Audit Agent

Локальный CLI-инструмент для аудита Linux-хоста с plugin system, JSON/PDF-отчётами
и интеграцией с SecurITM.

## Текущее состояние

Проект уже умеет:
- запускать локальные проверки безопасности;
- формировать `AuditReport`;
- сохранять отчёты в JSON;
- сохранять PDF-отчёт при наличии зависимостей;
- искать и создавать актив в SecurITM;
- создавать или переиспользовать открытые задачи в SecurITM по результатам `FAIL`;
- сохранять fallback JSON для задач, которые не удалось синхронизировать с API.

Что важно понимать:
- рабочий конфиг **не хранится** в Git;
- в репозитории хранится только шаблон `configs/audit.yml.example`;
- создание задач в SecurITM зависит от фактического поведения облачного API и остаётся самым нестабильным участком проекта.

## Управление Проектом

- План исправлений и техдолга: `docs/BACKLOG.md`
- Правила работы с репозиторием: `CONTRIBUTING.md`
- Changelog: `CHANGELOG.md`
- English README: `README.en.md`
- Политика ручных проверок: `docs/MANUAL_CHECKS.md`

## Первый запуск

Сначала подготовьте рабочий конфиг:

```bash
cp configs/audit.yml.example configs/audit.yml
```

После этого заполните в `configs/audit.yml`:
- параметры SecurITM;
- тип актива;
- шаблон импорта;
- при необходимости `author_uuid` / `responsible_uuid`.

Важно:
- для `--dry-run` и чтения структуры проекта CLI умеет использовать `configs/audit.yml.example`, если `configs/audit.yml` ещё не создан;
- для реальной локальной настройки и интеграции с SecurITM всё равно нужен собственный `configs/audit.yml`.

## Быстрый старт из репозитория

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install ".[pdf]"   # опционально, если нужен PDF-отчёт
cp configs/audit.yml.example configs/audit.yml
python -m securitm_audit_agent -c configs/audit.yml --dry-run
python -m securitm_audit_agent -c configs/audit.yml -o audit-report.json
```

Быстрый просмотр из чистого клона:

```bash
python -m securitm_audit_agent --dry-run
```

## Установка пакета

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

## Все флаги CLI

- `-c`, `--config` — путь к конфигурации YAML/JSON. По умолчанию `configs/audit.yml`.
- `-o`, `--output` — путь к JSON-отчёту. Переопределяет `audit.output.json`.
- `--no-api` — отключить интеграцию с SecurITM.
- `--dry-run` — вывести список проверок и выйти.
- `-v`, `--verbose` — уровень логирования. Поддерживаются `-v` и `-vv`.

## Конфигурация

Основной шаблон лежит в:

```text
configs/audit.yml.example
```

Рабочий файл:

```text
configs/audit.yml
```

Он игнорируется Git и предназначен только для локальной среды.

Ключевые блоки:
- `audit.checks.builtin` — включить built-in проверки.
- `audit.checks.enabled` — список активных `check_id`.
- `audit.plugins` — список модулей плагинов.
- `audit.params` — параметры проверок.
- `audit.output.json` — путь к JSON-отчёту.
- `audit.output.pdf` — путь к PDF-отчёту.
- `audit.output.pdf_font_path` — путь к TTF-шрифту с кириллицей.

## PDF

PDF включается через `audit.output.pdf`.

Для русских символов нужен TTF-шрифт с поддержкой кириллицы, например:

```text
/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf
```

Если `reportlab` или шрифт недоступны, JSON-отчёт всё равно будет создан,
а ошибка PDF будет только залогирована.

`requirements.txt` содержит только базовые runtime-зависимости. Поддержка PDF
подключается отдельно через extra `.[pdf]`.

## Плагины

В проект включён базовый плагин:

```text
securitm_audit_agent.plugins.met_rekom_linux
```

Он покрывает набор baseline-проверок по методическим рекомендациям для Linux.
Часть требований остаётся manual-only и возвращает `SKIP`.
Подробности вынесены в `docs/MANUAL_CHECKS.md`.
По умолчанию manual-only проверки **не** включены в `configs/audit.yml.example`,
чтобы baseline-профиль оставался автоматическим и не зашумлял first-run.

Подключение плагина через конфиг:

```yaml
audit:
  plugins:
    - "securitm_audit_agent.plugins.met_rekom_linux"
  checks:
    builtin: false
```

Каждый плагин должен экспортировать функцию:

```python
register(registry)
```

## Интеграция с SecurITM

Для включения интеграции:

1. В `configs/audit.yml` установите `securitm.enabled: true`.
2. Экспортируйте токен:

```bash
export SECURITM_TOKEN="ВАШ_ТОКЕН"
```

Основные поля:
- `securitm.base_url` — адрес сервиса, для облака `https://service.securitm.ru`.
- `securitm.token_env` — имя переменной окружения с токеном.
- `securitm.assets.asset_type_slug` — slug типа актива.
- `securitm.assets.import_template` — шаблон импорта.
- `securitm.assets.import_fields` — поля импорта, обычно через `{hostname}`, `{fqdn}`, `{ip}`.
- `securitm.tasks.author_uuid` — UUID автора задачи.
- `securitm.tasks.responsible_uuid` — UUID ответственного.
- `securitm.tasks.fallback_output_json` — JSON-файл для задач, которые не удалось синхронизировать с API.

## Известные ограничения

- CLI по умолчанию работает и от `configs/audit.yml.example`, но для реальной локальной настройки и интеграции нужен собственный `configs/audit.yml`.
- Создание задач в SecurITM пока нельзя считать полностью надёжным: облачный API в разных сценариях ведёт себя нестабильно.
- При сбое task API агент может сохранить неотправленные payload в `securitm-task-fallback.json` для ручной обработки.
- Часть baseline-checks остаётся ручной и возвращает `SKIP`.
- Часть baseline-checks может давать шумные `FAIL` на системных аккаунтах и специфичных системных путях.

## Тесты

Локальный запуск:

```bash
pytest
```
