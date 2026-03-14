from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ConfigError(ValueError):
    pass


@dataclass(slots=True)
class AppConfig:
    snapshot_count: int = 8
    snapshot_interval_seconds: float = 1.0
    suspicion_threshold: float = 0.65
    min_hits: int = 5
    min_distinct_local_ports: int = 3
    monitor_loop_interval_seconds: float = 5.0
    alert_cooldown_seconds: int = 120
    log_file: str = "logs/secopsbuddy.log"
    log_error_file: str = "logs/errors.log"
    log_results_file: str = "logs/results.log"
    log_actions_file: str = "logs/actions.log"
    log_events_file: str = "logs/events.log"
    log_threats_file: str = "logs/threats.log"
    mitre_log_dir: str = "logs/mitre"
    bot_events_file: str = "runtime/bot_events.jsonl"
    bot_pid_file: str = "runtime/bot.pid"
    bot_log_file: str = "logs/bot.log"
    bot_error_log_file: str = "logs/bot_errors.log"
    dry_run: bool = True
    block_private_ips: bool = False
    allowed_remote_ips: list[str] = field(default_factory=list)
    allowed_remote_ports: list[int] = field(default_factory=list)
    allowed_process_names: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    suppressed_ports: list[int] = field(default_factory=list)
    collector_command_preference: list[str] = field(
        default_factory=lambda: ["ss_tunp", "ss_tun", "ss_tpn", "netstat_tunp"]
    )

    @classmethod
    def from_dict(cls, raw: dict) -> "AppConfig":
        defaults = cls()
        try:
            config = cls(
                snapshot_count=int(raw.get("snapshot_count", defaults.snapshot_count)),
                snapshot_interval_seconds=float(
                    raw.get(
                        "snapshot_interval_seconds",
                        defaults.snapshot_interval_seconds,
                    )
                ),
                suspicion_threshold=float(
                    raw.get("suspicion_threshold", defaults.suspicion_threshold)
                ),
                min_hits=int(raw.get("min_hits", defaults.min_hits)),
                min_distinct_local_ports=int(
                    raw.get(
                        "min_distinct_local_ports",
                        defaults.min_distinct_local_ports,
                    )
                ),
                monitor_loop_interval_seconds=float(
                    raw.get(
                        "monitor_loop_interval_seconds",
                        defaults.monitor_loop_interval_seconds,
                    )
                ),
                alert_cooldown_seconds=int(
                    raw.get("alert_cooldown_seconds", defaults.alert_cooldown_seconds)
                ),
                log_file=str(raw.get("log_file", defaults.log_file)),
                log_error_file=str(raw.get("log_error_file", defaults.log_error_file)),
                log_results_file=str(raw.get("log_results_file", defaults.log_results_file)),
                log_actions_file=str(raw.get("log_actions_file", defaults.log_actions_file)),
                log_events_file=str(raw.get("log_events_file", defaults.log_events_file)),
                log_threats_file=str(raw.get("log_threats_file", defaults.log_threats_file)),
                mitre_log_dir=str(raw.get("mitre_log_dir", defaults.mitre_log_dir)),
                bot_events_file=str(raw.get("bot_events_file", defaults.bot_events_file)),
                bot_pid_file=str(raw.get("bot_pid_file", defaults.bot_pid_file)),
                bot_log_file=str(raw.get("bot_log_file", defaults.bot_log_file)),
                bot_error_log_file=str(raw.get("bot_error_log_file", defaults.bot_error_log_file)),
                dry_run=_parse_bool(raw.get("dry_run", defaults.dry_run)),
                block_private_ips=_parse_bool(
                    raw.get("block_private_ips", defaults.block_private_ips)
                ),
                allowed_remote_ips=_parse_string_list(
                    raw.get("allowed_remote_ips", defaults.allowed_remote_ips),
                    field_name="allowed_remote_ips",
                ),
                allowed_remote_ports=_parse_port_list(
                    raw.get("allowed_remote_ports", defaults.allowed_remote_ports),
                    field_name="allowed_remote_ports",
                ),
                allowed_process_names=_parse_string_list(
                    raw.get("allowed_process_names", defaults.allowed_process_names),
                    field_name="allowed_process_names",
                    lower=True,
                ),
                allowed_cidrs=_parse_cidr_list(
                    raw.get("allowed_cidrs", defaults.allowed_cidrs),
                    field_name="allowed_cidrs",
                ),
                suppressed_ports=_parse_port_list(
                    raw.get("suppressed_ports", defaults.suppressed_ports),
                    field_name="suppressed_ports",
                ),
                collector_command_preference=_parse_command_preference(
                    raw.get(
                        "collector_command_preference",
                        defaults.collector_command_preference,
                    )
                ),
            )
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"Некорректное значение в конфиге: {exc}") from exc

        if config.snapshot_count <= 0:
            raise ConfigError("snapshot_count должен быть > 0")
        if config.snapshot_interval_seconds < 0:
            raise ConfigError("snapshot_interval_seconds должен быть >= 0")
        if not 0 <= config.suspicion_threshold <= 1:
            raise ConfigError("suspicion_threshold должен быть в диапазоне [0, 1]")
        if config.min_hits <= 0:
            raise ConfigError("min_hits должен быть > 0")
        if config.min_distinct_local_ports <= 0:
            raise ConfigError("min_distinct_local_ports должен быть > 0")
        if config.monitor_loop_interval_seconds < 0:
            raise ConfigError("monitor_loop_interval_seconds должен быть >= 0")
        if config.alert_cooldown_seconds < 0:
            raise ConfigError("alert_cooldown_seconds должен быть >= 0")

        _ensure_path_value(config.log_file, "log_file")
        _ensure_path_value(config.log_error_file, "log_error_file")
        _ensure_path_value(config.log_results_file, "log_results_file")
        _ensure_path_value(config.log_actions_file, "log_actions_file")
        _ensure_path_value(config.log_events_file, "log_events_file")
        _ensure_path_value(config.log_threats_file, "log_threats_file")
        _ensure_path_value(config.mitre_log_dir, "mitre_log_dir")
        _ensure_path_value(config.bot_events_file, "bot_events_file")
        _ensure_path_value(config.bot_pid_file, "bot_pid_file")
        _ensure_path_value(config.bot_log_file, "bot_log_file")
        _ensure_path_value(config.bot_error_log_file, "bot_error_log_file")

        return config


def _ensure_path_value(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ConfigError(f"{field_name} не должен быть пустым")


def _parse_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on", "да"}:
            return True
        if lowered in {"0", "false", "no", "off", "нет"}:
            return False
        raise ValueError(f"Недопустимая строка bool: {value}")
    if isinstance(value, int):
        return bool(value)
    raise ValueError(f"Недопустимое bool-значение: {value!r}")


def _parse_command_preference(value: object) -> list[str]:
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
        if not items:
            raise ValueError("collector_command_preference не должен быть пустым")
        return items
    raise ValueError("collector_command_preference должен быть списком ключей команд")


def _parse_string_list(
    value: object,
    field_name: str,
    lower: bool = False,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f"{field_name} должен быть списком")

    items: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text:
            continue
        items.append(text.lower() if lower else text)
    return list(dict.fromkeys(items))


def _parse_port_list(value: object, field_name: str) -> list[int]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple, set)):
        raise ValueError(f"{field_name} должен быть списком портов")

    ports: list[int] = []
    for item in value:
        port = int(item)
        if port <= 0 or port > 65535:
            raise ValueError(f"{field_name}: порт вне диапазона 1..65535: {port}")
        ports.append(port)
    return list(dict.fromkeys(ports))


def _parse_cidr_list(value: object, field_name: str) -> list[str]:
    cidrs = _parse_string_list(value, field_name=field_name)
    normalized: list[str] = []
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        normalized.append(str(network))
    return list(dict.fromkeys(normalized))


def get_default_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "config" / "default_config.yaml"


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path) if path else get_default_config_path()

    if not config_path.exists():
        raise ConfigError(f"Файл конфига не найден: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Ошибка YAML в {config_path}: {exc}") from exc

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ConfigError(f"Корень конфига должен быть mapping: {config_path}")

    return AppConfig.from_dict(raw)
