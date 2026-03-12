# Установка SecOps Buddy

## Требования

- Linux-хост (проект ориентирован на Linux);
- Python `3.11+`;
- системная утилита `ss` (предпочтительно) или `netstat`;
- для режима `block`: `ufw` или `iptables`.

## Установка из репозитория

```bash
cd SecOps-Buddy-Remake
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Проверка установки

```bash
python -m secopsbuddy.main --list
python -m secopsbuddy.main --info t1030
```

## Первый запуск

Однократный цикл (удобно для диагностики):

```bash
python -m secopsbuddy.main --run t1030
```

Непрерывный мониторинг:

```bash
python -m secopsbuddy.main --run t1030 --continuous
```

Режим блокировки с безопасной эмуляцией:

```bash
python -m secopsbuddy.main --run t1030 --continuous --mode block --dry-run
```

Реальная блокировка через firewall:

```bash
sudo python -m secopsbuddy.main --run t1030 --continuous --mode block
```

## Пользовательский конфиг

По умолчанию используется `config/default_config.yaml`.

Чтобы запустить с другим YAML-файлом:

```bash
python -m secopsbuddy.main --run t1030 --continuous --config /path/to/config.yaml
```

## Следующий шаг

После установки перейдите к настройке параметров детектора и подавления шума:

- [Инструкция по настройке](configuration.md)
