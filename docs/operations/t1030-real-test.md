# Операции: реальный тест T1030

Этот сценарий нужен для практической проверки детектора `T1030` на безопасном
синтетическом трафике (без эксплуатации уязвимостей).

## Что делает скрипт

Скрипт `scripts/t1030_test_traffic.py` имеет 2 режима:

- `server`: поднимает TCP listener (точка приёма тестового трафика)
- `client`: создаёт много коротких исходящих TCP-соединений с небольшим payload

Такой паттерн имитирует поведение, похожее на T1030.

## Быстрый запуск

Терминал 1 (приёмник):

```bash
python scripts/t1030_test_traffic.py server --host 127.0.0.1 --port 9443
```

Терминал 2 (SecOps Buddy):

```bash
python -m secopsbuddy.main --run t1030 --continuous --monitor-interval-seconds 2
```

Терминал 3 (генерация тестового паттерна):

```bash
python scripts/t1030_test_traffic.py client \
  --target-host 127.0.0.1 \
  --target-port 9443 \
  --connections 150 \
  --payload-size 128 \
  --hold-ms 200 \
  --delay-ms 20
```

## Полезные параметры

- `--connections`: общее число коротких соединений
- `--hold-ms`: сколько держать соединение открытым
- `--delay-ms`: пауза между соединениями
- `--payload-size`: размер payload для каждой сессии
- `--max-connections` (server): авто-остановка сервера после N соединений

## Как понять, что тест успешен

Ожидаемый результат в выводе/логах SecOps Buddy:

- статус `suspicious` для `T1030`
- findings с повторяющимся `remote_ip:remote_port`
- рост `hit_count` и `distinct_local_ports`

## Важно

- Используйте только в своей тестовой среде.
- По умолчанию используется localhost (`127.0.0.1`).
- Если срабатывание слабое, увеличьте `connections` и `hold-ms`, либо временно
  снизьте `suspicion_threshold` в конфиге для калибровки.

См. также: [Полный гайд по тестированию](../testing.md).
