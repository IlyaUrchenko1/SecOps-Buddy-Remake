# Операции: мониторинг

## Одноразовый запуск

```bash
python -m secopsbuddy.main --run t1030
```

Команда выполняет один детект-цикл и завершается.

## Непрерывный мониторинг

```bash
python -m secopsbuddy.main --run t1030 --continuous
```

Программа запускает циклы детектирования бесконечно, пока не будет остановлена через `Ctrl+C`.

## Непрерывный режим с интервалом

```bash
python -m secopsbuddy.main --run t1030 --continuous --monitor-interval-seconds 10
```

`--monitor-interval-seconds` задает паузу между циклами.

## Ограничение числа циклов

```bash
python -m secopsbuddy.main --run t1030 --continuous --max-cycles 5
```

Полезно для теста, демонстрации и CI.

## Блокировка подозрительных IP

```bash
sudo python -m secopsbuddy.main --run t1030 --continuous --mode block
```

Для безопасного тестирования:

```bash
python -m secopsbuddy.main --run t1030 --continuous --mode block --dry-run
```

## Telegram уведомления

При наличии запущенного `run_bot`:

- при старте детектора отправляется уведомление `detector_started`
- при остановке детектора отправляется уведомление `detector_stopped`
- при suspicious результате отправляется полный alert
- при успешной блокировке отправляется уведомление `threat_mitigated`
