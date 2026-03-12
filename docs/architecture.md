# Архитектура SecOps Buddy

## Модули

- `secopsbuddy/main.py`: точка входа и маршрутизация CLI
- `secopsbuddy/cli.py`: аргументы командной строки
- `secopsbuddy/config.py`: загрузка и валидация YAML-конфига
- `secopsbuddy/registry.py`: реестр детекторов
- `secopsbuddy/runner.py`: цикл запуска детекторов и режимы `monitor/block`
- `secopsbuddy/collectors/network_snapshot.py`: сбор сетевых snapshot-ов через `ss`/`netstat`
- `secopsbuddy/detectors/t1030.py`: эвристика MITRE ATT&CK T1030
- `secopsbuddy/responders/alert.py`: форматирование вывода
- `secopsbuddy/responders/firewall.py`: блокировка IP через `ufw`/`iptables`
- `secopsbuddy/logging_setup.py`: многоканальное логирование
- `secopsbuddy/event_dispatcher.py`: шина событий и sink-механизм
- `secopsbuddy/bot/worker.py`: aiogram polling worker
- `secopsbuddy/bot/control.py`: управление бот-процессом (`run_bot`)
- `secopsbuddy/bot/handlers.py`: handlers команд и callback
- `secopsbuddy/bot/keyboards.py`: reply/inline клавиатуры
- `secopsbuddy/bot/notifier.py`: форматирование событий в уведомления
- `secopsbuddy/bot/settings.py`: чтение `.env` настроек бота

## Поток выполнения

1. CLI читает команду и конфиг
2. Инициализируется логирование
3. Через реестр выбирается детектор
4. Runner запускает один цикл или непрерывный мониторинг
5. Detector собирает snapshot-ы и считает `suspicion_score`
6. Результат пишется в консоль и в специализированные логи
7. В режиме block вызывается firewall responder
8. События пишутся в event stream
9. Telegram worker читает stream и рассылает алерты

## Расширяемость

- Новый детектор добавляется как класс, реализующий `BaseDetector`
- Реестр расширяется одной регистрацией
- Новые каналы интеграций добавляются как sink в `event_dispatcher.py`
- Можно подключить Telegram/Grafana/SIEM без переписывания ядра
