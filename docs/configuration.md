# Настройка SecOps Buddy

SecOps Buddy читает YAML-конфиг и валидирует его при старте.

Файл по умолчанию: `config/default_config.yaml`.

## Как применить свой конфиг

```bash
python -m secopsbuddy.main --run t1030 --continuous --config /path/to/config.yaml
```

## Ключевые параметры

### Детектор и scoring

| Параметр | Назначение | Значение по умолчанию |
| --- | --- | --- |
| `snapshot_count` | Количество snapshot-ов соединений за один цикл | `8` |
| `snapshot_interval_seconds` | Пауза между snapshot-ами | `1.0` |
| `suspicion_threshold` | Порог `score` для suspicious | `0.65` |
| `min_hits` | Минимум повторов соединений для срабатывания | `5` |
| `min_distinct_local_ports` | Минимум разных локальных портов для срабатывания | `3` |

### Цикл мониторинга и алерты

| Параметр | Назначение | Значение по умолчанию |
| --- | --- | --- |
| `monitor_loop_interval_seconds` | Пауза между циклами в `--continuous` | `5.0` |
| `alert_cooldown_seconds` | Подавление дублей алертов в непрерывном режиме | `120` |

### Режим блокировки

| Параметр | Назначение | Значение по умолчанию |
| --- | --- | --- |
| `dry_run` | Эмуляция firewall-действий без реальной блокировки | `true` |
| `block_private_ips` | Разрешить блокировку private IP | `false` |

### Allowlist и suppressions

| Параметр | Что исключает из анализа |
| --- | --- |
| `allowed_remote_ips` | Полностью доверенные удалённые IP |
| `allowed_remote_ports` | Доверенные удалённые порты |
| `allowed_process_names` | Доверенные имена процессов |
| `allowed_cidrs` | Доверенные CIDR-сети |
| `suppressed_ports` | Локальные порты, которые нужно подавить |

Важно:

- `suppressed_ports` - это именно локальные порты процесса, не удалённые;
- allowlist/suppressions исключаются до scoring, чтобы снижать false positive;
- порты должны быть в диапазоне `1..65535`.

### Логи, события, бот

| Параметр | Назначение |
| --- | --- |
| `log_file`, `log_error_file`, `log_results_file`, `log_actions_file`, `log_events_file` | Пути к логам приложения |
| `mitre_log_dir` | Каталог MITRE-логов |
| `bot_events_file` | JSONL-поток событий для бота |
| `bot_pid_file`, `bot_log_file`, `bot_error_log_file` | Файлы процесса и логов бота |

### Collector

| Параметр | Назначение |
| --- | --- |
| `collector_command_preference` | Порядок команд сбора (`ss_tunp`, `ss_tun`, `ss_tpn`, `netstat_tunp`) |

## Примеры настройки Allowlist / suppressions

### Пример 1: доверенные адреса и процессы

```yaml
allowed_remote_ips:
  - 198.51.100.10
allowed_cidrs:
  - 203.0.113.0/24
allowed_process_names:
  - backup-agent
allowed_remote_ports:
  - 443
```

### Пример 2: подавление локальных сервисных портов

```yaml
suppressed_ports:
  - 5353
  - 1900
```

## Как работает cooldown дублей

Параметр: `alert_cooldown_seconds`.

- cooldown применяется в `--continuous` режиме;
- если тот же fingerprint алерта повторился раньше таймаута, алерт подавляется;
- fingerprint строится по `mitre_id + remote_ip + remote_port + process_name`;
- при `0` cooldown отключается.

Пример:

```yaml
alert_cooldown_seconds: 180
```

## Рекомендуемый стартовый профиль

```yaml
dry_run: true
alert_cooldown_seconds: 120
allowed_remote_ips: []
allowed_remote_ports: []
allowed_process_names: []
allowed_cidrs: []
suppressed_ports: []
```

Сначала соберите baseline в `dry_run`, затем постепенно добавляйте allowlist/suppressions
для шумных, но легитимных сценариев.
