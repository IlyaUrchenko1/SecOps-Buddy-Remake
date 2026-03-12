# Операции: логирование

## Лог-файлы

По умолчанию используются следующие файлы:

- `logs/secopsbuddy.log` — общий лог приложения
- `logs/errors.log` — только ошибки
- `logs/results.log` — агрегированные результаты детект-циклов
- `logs/actions.log` — действия блокировки/response
- `logs/events.log` — универсальный поток событий
- `logs/mitre/t1030.log` — подробные события конкретной MITRE-техники
- `logs/bot.log` — общий лог Telegram бота
- `logs/bot_errors.log` — ошибки Telegram бота

## Event stream для бота

- `runtime/bot_events.jsonl` — JSONL-поток событий для нотификаций
- Пишется из `DetectionRunner` через `FileEventSink`
- Читается ботом в `worker.py`

## Что где смотреть

- Нужно быстро понять состояние системы: `secopsbuddy.log`
- Нужно разбирать инциденты: `results.log` + `mitre/t1030.log`
- Нужно проверить, что реально блокировалось: `actions.log`
- Нужно подключать внешние интеграции: `events.log` и `runtime/bot_events.jsonl`

## Масштабирование логов и уведомлений

В проекте есть `event_dispatcher.py`.

Текущие sink-реализации:

- Logger sink
- File sink

Дальше можно добавлять:

- Telegram sink
- Grafana/Loki sink
- SIEM sink
- Webhook sink
