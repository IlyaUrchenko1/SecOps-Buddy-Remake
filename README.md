# SecOps Buddy (MVP)

SecOps Buddy — легковесный модульный CLI-инструмент для Linux, который помогает обнаруживать техники MITRE ATT&CK.

В текущем MVP реализован один детектор:

- **MITRE ATT&CK T1030** — Data Transfer Size Limits

## Что реализовано

- модульная архитектура и реестр детекторов
- CLI-команды для списка, информации и запуска детектора
- рабочий детектор T1030 на основе snapshot-эвристики исходящих соединений
- коллектор сети через `ss` с fallback на `netstat`
- вывод алертов в консоль и запись логов в файл
- режим `block` для попытки блокировки IP через `ufw`/`iptables`
- YAML-конфигурация
- базовые unit-тесты на `pytest`

## MITRE mapping

- `t1030` -> `T1030` (Data Transfer Size Limits)

Важно: текущая версия **не измеряет точный размер передаваемых блоков данных**. Детектор использует поведенческие proxy-признаки (повторяемость коротких исходящих соединений).

## Структура проекта

```text
secopsbuddy/
├── __init__.py
├── main.py
├── cli.py
├── config.py
├── logging_setup.py
├── models.py
├── registry.py
├── runner.py
├── collectors/
│   ├── __init__.py
│   └── network_snapshot.py
├── detectors/
│   ├── __init__.py
│   ├── base.py
│   └── t1030.py
├── responders/
│   ├── __init__.py
│   ├── alert.py
│   └── firewall.py
├── utils/
│   ├── __init__.py
│   └── time_utils.py
config/
└── default_config.yaml
logs/
└── .gitkeep
tests/
├── __init__.py
├── test_registry.py
├── test_t1030_detector.py
└── test_firewall.py
requirements.txt
README.md
pyproject.toml
```

## Установка

Требования:

- Linux
- Python 3.11+

Установка:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Запуск

Показать список детекторов:

```bash
python -m secopsbuddy.main --list
```

Показать информацию о детекторе:

```bash
python -m secopsbuddy.main --info t1030
```

Запустить детектор:

```bash
python -m secopsbuddy.main --run t1030
```

Запустить детектор в режиме блокировки:

```bash
sudo python -m secopsbuddy.main --run t1030 --mode block
```

Запустить с явным конфигом:

```bash
python -m secopsbuddy.main --run t1030 --config config/default_config.yaml
```

JSON-вывод результата:

```bash
python -m secopsbuddy.main --run t1030 --json
```

Принудительный dry-run:

```bash
python -m secopsbuddy.main --run t1030 --mode block --dry-run
```

## Конфиг

Файл по умолчанию: `config/default_config.yaml`

Ключевые параметры:

- `snapshot_count`
- `snapshot_interval_seconds`
- `suspicion_threshold`
- `min_hits`
- `min_distinct_local_ports`
- `log_file`
- `dry_run`
- `block_private_ips`
- `collector_command_preference`

## Логика T1030 (честный MVP)

Детектор собирает серию сетевых snapshot-ов и группирует соединения по:

- remote IP
- remote port
- protocol
- process name

Далее считаются признаки:

- `hit_count`
- число уникальных локальных портов
- сколько snapshot-ов содержит паттерн
- дополнительные штрафы/бонусы

По этим признакам формируется `suspicion_score` в диапазоне `[0..1]`.

Это **эвристика**, а не точная измерительная модель размера передачи. Архитектура оставляет место для более точного collector-а на базе pcap/eBPF.

## Режим block

В режиме `--mode block` при suspicious findings система:

1. пробует `ufw`
2. если `ufw` нет — пробует `iptables`
3. не блокирует loopback/приватные/локальные/зарезервированные IP (если `block_private_ips: false`)
4. при нехватке прав или отсутствии команд не падает, а возвращает понятное сообщение

## Логирование

Логи пишутся:

- в консоль
- в файл (`log_file`, по умолчанию `logs/secopsbuddy.log`)

Логируются запуск, параметры, ошибки collector-а, findings и действия firewall.

## Тесты

Запуск:

```bash
pytest
```

Покрыто минимумом:

- реестр детекторов
- scoring T1030 на мок-данных
- защита от блокировки приватных IP

## Ограничения MVP

- без byte-level анализа трафика
- без pcap/eBPF в текущей версии
- возможны false positive/false negative
- зависит от наличия системных утилит (`ss`/`netstat`, опционально `ufw`/`iptables`)

## Как добавить новый детектор

1. Создать класс детектора в `secopsbuddy/detectors/`, реализующий `BaseDetector`.
2. Добавить метаданные (`detector_id`, `mitre_id`, `name`, `description`) и `run()`.
3. Зарегистрировать детектор в `create_default_registry()`.
4. Добавить тесты в `tests/`.
5. Обновить README (раздел MITRE mapping).

## Безопасность

- по умолчанию `dry_run: true`
- перед блокировкой всегда выполняется валидация IP
- subprocess вызывается без `shell=True`
