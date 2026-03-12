from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from secopsbuddy.config import AppConfig, ConfigError, load_config


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="run_bot")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--start", action="store_true", help="Запустить бота")
    action.add_argument("--stop", action="store_true", help="Остановить бота")
    action.add_argument("--status", action="store_true", help="Статус процесса бота")
    parser.add_argument("--foreground", action="store_true", help="Не уходить в фон")
    parser.add_argument("--config", default=None, help="Путь к YAML-конфигу")
    parser.add_argument("--env-file", default=".env", help="Путь к .env")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"[ОШИБКА] Не удалось загрузить конфиг: {exc}")
        return 2

    pid_file = Path(config.bot_pid_file)

    if args.start:
        return _start_bot(config, args.config, args.env_file, args.foreground, pid_file)

    if args.stop:
        return _stop_bot(pid_file)

    return _status_bot(pid_file)


def _start_bot(
    config: AppConfig,
    config_path: str | None,
    env_file: str,
    foreground: bool,
    pid_file: Path,
) -> int:
    existing_pid = _read_pid(pid_file)
    if existing_pid and _is_process_alive(existing_pid):
        print(f"Бот уже запущен (pid={existing_pid}).")
        return 0

    if existing_pid and not _is_process_alive(existing_pid):
        pid_file.unlink(missing_ok=True)

    command = [sys.executable, "-m", "secopsbuddy.bot.worker", "--env-file", env_file]
    if config_path:
        command.extend(["--config", config_path])

    if foreground:
        print("Запуск бота в foreground режиме...")
        completed = subprocess.run(command)
        return completed.returncode

    log_path = Path(config.bot_log_file)
    err_path = Path(config.bot_error_log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    err_path.parent.mkdir(parents=True, exist_ok=True)
    pid_file.parent.mkdir(parents=True, exist_ok=True)

    with log_path.open("a", encoding="utf-8") as out, err_path.open("a", encoding="utf-8") as err:
        process = subprocess.Popen(
            command,
            stdout=out,
            stderr=err,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )

    pid_file.write_text(str(process.pid), encoding="utf-8")
    print(f"Бот запущен в фоне (pid={process.pid}).")
    print(f"Лог бота: {log_path}")
    print(f"Лог ошибок бота: {err_path}")
    print("Остановка: run_bot --stop")
    return 0


def _stop_bot(pid_file: Path) -> int:
    pid = _read_pid(pid_file)
    if pid is None:
        print("PID-файл бота не найден. Возможно, бот не запущен.")
        return 0

    if not _is_process_alive(pid):
        pid_file.unlink(missing_ok=True)
        print("Процесс из PID-файла не найден. PID-файл очищен.")
        return 0

    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        print(f"[ОШИБКА] Не удалось отправить SIGTERM: {exc}")
        return 1

    for _ in range(20):
        if not _is_process_alive(pid):
            pid_file.unlink(missing_ok=True)
            print("Бот остановлен.")
            return 0
        time.sleep(0.5)

    try:
        os.kill(pid, signal.SIGKILL)
    except OSError as exc:
        print(f"[ОШИБКА] Не удалось выполнить принудительную остановку: {exc}")
        return 1

    pid_file.unlink(missing_ok=True)
    print("Бот остановлен принудительно.")
    return 0


def _status_bot(pid_file: Path) -> int:
    pid = _read_pid(pid_file)
    if pid is None:
        print("Бот не запущен.")
        return 0

    if _is_process_alive(pid):
        print(f"Бот запущен (pid={pid}).")
        return 0

    print("Бот не запущен, PID-файл устарел.")
    return 1


def _read_pid(pid_file: Path) -> int | None:
    if not pid_file.exists():
        return None

    raw = pid_file.read_text(encoding="utf-8").strip()
    if not raw.isdigit():
        return None
    return int(raw)


def _is_process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
