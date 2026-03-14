# Операции: логирование

## Лог-файлы

По умолчанию используются следующие файлы:

- `logs/secopsbuddy.log` - общий лог приложения
- `logs/errors.log` - только ошибки
- `logs/results.log` - агрегированные результаты детект-циклов
- `logs/threats.log` - краткий threat log (1 строка = 1 угроза)
- `logs/actions.log` - действия блокировки/response
- `logs/events.log` - универсальный поток событий
- `logs/mitre/t1030.log` - подробные события конкретной MITRE-техники
- `logs/bot.log` - общий лог Telegram бота
- `logs/bot_errors.log` - ошибки Telegram бота

## Event stream для бота

- `runtime/bot_events.jsonl` - JSONL-поток событий для нотификаций
- Пишется из `DetectionRunner` через `FileEventSink`
- Читается ботом в `worker.py`

## Что где смотреть

- Нужно быстро понять состояние системы: `secopsbuddy.log`
- Нужен короткий список угроз: `threats.log`
- Нужно разбирать инциденты подробно: `results.log` + `mitre/t1030.log`
- Нужно проверить, что реально блокировалось: `actions.log`
- Нужно подключать внешние интеграции: `events.log` и `runtime/bot_events.jsonl`

## Формат threat log

Каждая строка в `logs/threats.log` - это отдельный JSON-объект `threat_detected`.

В записи есть:

- `remote_ip`, `remote_port`, `process_name`
- `score`, `hit_count`, `distinct_local_ports`
- `cycle`, `mode`, `timestamp`, `window_seconds`

## Шум в консоли

Детальные технические логи (`results/events/actions/mitre/threats`) пишутся в файлы.
Консоль оставлена более компактной для оперативного чтения.
