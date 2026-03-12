# SecOps Buddy (MVP)

SecOps Buddy — модульный Linux CLI-инструмент для обнаружения MITRE ATT&CK техник.

Текущая реализация включает детектор:

- `t1030` -> `T1030` (Data Transfer Size Limits)

## Быстрый старт

Установка:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Список детекторов:

```bash
python -m secopsbuddy.main --list
```

Информация о детекторе:

```bash
python -m secopsbuddy.main --info t1030
```

Однократный запуск:

```bash
python -m secopsbuddy.main --run t1030
```

Непрерывный мониторинг:

```bash
python -m secopsbuddy.main --run t1030 --continuous
```

Непрерывный мониторинг с блокировкой:

```bash
sudo python -m secopsbuddy.main --run t1030 --continuous --mode block
```

Безопасная проверка блокировок:

```bash
python -m secopsbuddy.main --run t1030 --continuous --mode block --dry-run
```

## Telegram бот

Пример `.env`:

```env
SECOPSBUDDY_BOT_TOKEN=...
SECOPSBUDDY_BOT_ALLOWED_IDS=111111111,222222222
```

Запуск бота в фоне:

```bash
run_bot --start
```

или

```bash
python -m secopsbuddy.bot.control --start
```

Остановка:

```bash
run_bot --stop
```

или

```bash
python -m secopsbuddy.bot.control --stop
```

Проверка статуса:

```bash
run_bot --status
```

или

```bash
python -m secopsbuddy.bot.control --status
```

## Почему запуск завершился после одного прогона

Команда `--run` по умолчанию выполняет один цикл и завершается.

Это удобно для диагностики и CI.

Для постоянного мониторинга нужен флаг `--continuous`.

## Логи

По умолчанию создаются:

- `logs/secopsbuddy.log`
- `logs/errors.log`
- `logs/results.log`
- `logs/actions.log`
- `logs/events.log`
- `logs/mitre/t1030.log`
- `logs/bot.log`
- `logs/bot_errors.log`

## Важное ограничение MVP

Текущий T1030-детектор работает как поведенческая эвристика по snapshot-ам `ss`/`netstat`.

Он не измеряет размер передаваемых чанков на packet-level.

## Документация

- [Индекс документации](docs/README.md)
- [Архитектура](docs/architecture.md)
- [MITRE T1030](docs/mitre/T1030.md)
- [Операции: мониторинг](docs/operations/monitoring.md)
- [Операции: логирование](docs/operations/logging.md)
- [Операции: Telegram бот](docs/operations/bot.md)
- [План улучшений](docs/improvements.md)
