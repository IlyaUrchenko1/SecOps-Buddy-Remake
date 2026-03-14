# Операции: Telegram бот

## Зависимости

- `aiogram 3.x`
- `python-dotenv`

## Настройка `.env`

В репозитории есть шаблон: `.env.example`.

```bash
cp .env.example .env
```

Заполни значения:

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

## Команды и кнопки

Команды:

- `/start` - приветствие и базовая справка
- `/status` - текущее состояние
- `/mute` - включить/выключить mute алертов
- `/help` - краткая справка

Reply keyboard:

- `Статус`, `Последние алерты`, `Уведомления`, `Помощь`

Inline keyboard:

- `ACK`, `MITRE`

## Что делает бот

- при старте детектора отправляет lifecycle-уведомление
- при остановке детектора отправляет lifecycle-уведомление
- при `suspicious` отправляет alert
- при `threat_mitigated` отправляет уведомление о нейтрализации
- при ошибках детектирования отправляет error-уведомление

## Логи бота

- `logs/bot.log` - общий лог бота
- `logs/bot_errors.log` - ошибки бота

## Архитектура

- Детектор и бот связаны через event stream (`runtime/bot_events.jsonl`)
- Бот читает события асинхронно и рассылает их allowlist-пользователям
- Для добавления новых каналов уведомлений можно расширять `EventSink`
