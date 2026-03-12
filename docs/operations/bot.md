# Операции: Telegram бот

## Зависимости

- `aiogram 3.x`
- `python-dotenv`

## Настройка `.env`

Скопируй `.env.example` в `.env` и заполни значения:

```env
SECOPSBUDDY_BOT_TOKEN=...
SECOPSBUDDY_BOT_ALLOWED_IDS=111111111,222222222
SECOPSBUDDY_BOT_NAME=SecOps Buddy
SECOPSBUDDY_BOT_EVENTS_FILE=runtime/bot_events.jsonl
```

## Запуск бота как отдельного процесса

Запуск в фоне:

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

Статус:

```bash
run_bot --status
```

или

```bash
python -m secopsbuddy.bot.control --status
```

Foreground-режим:

```bash
run_bot --start --foreground
```

или

```bash
python -m secopsbuddy.bot.control --start --foreground
```

## Что делает бот

- при старте детектора отправляет уведомление о запуске MITRE
- при остановке детектора отправляет уведомление о завершении
- при `suspicious` отправляет полный alert
- при `threat_mitigated` отправляет уведомление о блокировке IP
- при ошибках детектирования отправляет error-уведомление

## Кнопки и UX

- Reply keyboard: `Статус`, `Последние алерты`, `Mute/Unmute`, `Помощь`
- Inline keyboard: `ACK ✅`, `MITRE`
- `delete_webhook` вызывается при запуске worker

## Логи бота

- `logs/bot.log` — общий лог бота
- `logs/bot_errors.log` — ошибки бота

## Архитектура и масштабирование

- Детектор и бот связаны через event stream (`runtime/bot_events.jsonl`)
- Бот читает события асинхронно и рассылает сообщения allowlist-пользователям
- Для добавления новых каналов уведомлений можно расширять `EventSink`
