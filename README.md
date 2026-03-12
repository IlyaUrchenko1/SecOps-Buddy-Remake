# SecOps Buddy

SecOps Buddy - модульный Python-инструмент для Linux (HIDS), который обнаруживает
подозрительную активность на хосте и техники MITRE ATT&CK.

Текущая реализация включает детектор:

- `t1030` -> `T1030` (Data Transfer Size Limits)
## Что делает проект

- запускает детекторы в `monitor` или `block` режиме;
- в непрерывном режиме мониторинга контролирует повторяющиеся алерты через cooldown;
- поддерживает suppressions/allowlist для снижения false positive;
- отправляет события в event stream для внешних интеграций (включая Telegram-бота).

## Быстрый старт

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m secopsbuddy.main --list
python -m secopsbuddy.main --run t1030 --continuous
```

Проверка блокировок в безопасном режиме:

```bash
python -m secopsbuddy.main --run t1030 --continuous --mode block --dry-run
```

## Полная документация

- [Полная инструкция по установке](docs/installation.md)
- [Полная инструкция по настройке (включая allowlist/suppressions и cooldown)](docs/configuration.md)
- [Индекс всей документации](docs/README.md)

## Ограничение MVP

T1030-детектор работает как поведенческая эвристика по snapshot-ам `ss`/`netstat`.
Он не измеряет объём передачи данных на packet-level.
