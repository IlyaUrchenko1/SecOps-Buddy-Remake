# Тестирование SecOps Buddy

Этот документ собирает в одном месте все сценарии проверки: внутренние `pytest`-тесты, практический мониторинг `T1030`, проверку `--mode block` и материалы для отчёта (скриншоты).

## Что покрывают тесты

`pytest`-набор проверяет внутреннюю логику проекта без реальных атак и без изменения firewall:

- детектор `T1030` (поиск паттерна, score, allowlist/suppressions, safe-case);
- `DetectionRunner` (цикл, cooldown, публикация событий);
- `EventDispatcher` и event sinks;
- firewall responder (что можно/нельзя блокировать);
- unit/integration/e2e/load сценарии в отдельных каталогах.

## Структура тестов

```text
tests/
  unit/
  integration/
  e2e/
  load/
  test_t1030_detector.py
  test_runner.py
  test_dispatcher.py
  test_firewall_responder.py
```

## Команды pytest

Полный прогон:

```bash
python -m pytest -v
```

Ключевые файлы по T1030/runner/dispatcher/firewall:

```bash
python -m pytest -v tests/test_t1030_detector.py tests/test_runner.py tests/test_dispatcher.py tests/test_firewall_responder.py
```

Разделение по типам тестов:

```bash
python -m pytest -v tests/unit
python -m pytest -v tests/integration
python -m pytest -v tests/e2e
python -m pytest -v tests/load -m load
```

## Практический monitor-тест T1030

Сценарий нужен для живой демонстрации `suspicious`-результата в терминале.

### Шаг 1. Поднять приёмник тестового трафика

Локально:

```bash
python scripts/t1030_test_traffic.py server --host 127.0.0.1 --port 9443
```

Или на удалённом Linux-сервере:

```bash
python3 scripts/t1030_test_traffic.py server --host 0.0.0.0 --port 9443
```

### Шаг 2. Запустить детектор в monitor

```bash
python -m secopsbuddy.main --run t1030 --continuous --monitor-interval-seconds 2 --max-cycles 10
```

### Шаг 3. Сгенерировать паттерн соединений

Если сервер локальный:

```bash
python scripts/t1030_test_traffic.py client --target-host 127.0.0.1 --target-port 9443 --connections 150 --payload-size 128 --hold-ms 200 --delay-ms 20
```

Если сервер удалённый:

```bash
python scripts/t1030_test_traffic.py client --target-host <SERVER_IP> --target-port 9443 --connections 150 --payload-size 128 --hold-ms 200 --delay-ms 20
```

Ожидаемый результат: в одном из циклов будет `status=suspicious` и finding с `remote_ip`, `remote_port`, `score`.

## Практический тест `--mode block`

Сначала всегда проверка в `dry-run`, потом реальная блокировка.

### Dry-run

```bash
python -m secopsbuddy.main --run t1030 --continuous --mode block --dry-run --monitor-interval-seconds 2 --max-cycles 10
```

Сгенерируй трафик командой клиента из блока выше и проверь лог действий:

```bash
tail -n 30 logs/actions.log
```

### Реальная блокировка

```bash
sudo python -m secopsbuddy.main --run t1030 --continuous --mode block --monitor-interval-seconds 2 --max-cycles 10
```

Проверка правил firewall:

```bash
sudo ufw status numbered
```

Откат тестового правила:

```bash
sudo ufw delete deny from <SERVER_IP>
```

Важно: responder по умолчанию защищает от блокировки localhost/private-адресов. Для реального теста нужен публичный IP.

## Где смотреть результаты

- `logs/threats.log`: компактный threat log (одна строка = одна угроза);
- `logs/results.log`: результат каждого цикла детектирования;
- `logs/actions.log`: действия responder (dry-run/real);
- `runtime/bot_events.jsonl`: события для Telegram-бота.

## Чек-лист скриншотов для отчёта

### 1) Запуск pytest

Команда:

```bash
python -m pytest -v
```

На скриншоте должны быть видны:

- общее число `passed`;
- отсутствие `failed`;
- названия ключевых файлов: `test_t1030_detector.py`, `test_runner.py`, `test_dispatcher.py`.

### 2) Monitor-режим SecOps Buddy

Команда:

```bash
python -m secopsbuddy.main --run t1030 --continuous --monitor-interval-seconds 2 --max-cycles 10
```

На скриншоте должны быть видны:

- команда запуска;
- имя детектора (`t1030`);
- процесс циклов анализа;
- итоговый `suspicious`;
- значение `score`;
- удалённый адрес (`remote_ip:remote_port`).

### 3) Telegram-бот или `bot_events.jsonl`

Вариант через файл:

```bash
tail -n 20 runtime/bot_events.jsonl
```

На скриншоте должны быть видны:

- тип события (`detection_result` и/или `threat_mitigated`);
- указание на `T1030`;
- данные о процессе или IP;
- факт отправки/наличия уведомления.

### 4) Наличие отдельных тестов T1030

Команды:

```bash
ls tests
sed -n '1,160p' tests/test_t1030_detector.py
```

На скриншоте должно быть видно, что есть отдельный файл проверок `T1030`, а не только общие заглушки.
