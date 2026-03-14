from __future__ import annotations

import logging
from pathlib import Path


LOGGER_NAME = "secopsbuddy"
RESULTS_LOGGER_NAME = "secopsbuddy.results"
ACTIONS_LOGGER_NAME = "secopsbuddy.actions"
EVENTS_LOGGER_NAME = "secopsbuddy.events"
THREATS_LOGGER_NAME = "secopsbuddy.threats"
MITRE_LOGGER_PREFIX = "secopsbuddy.mitre"

_MITRE_LOG_DIR = Path("logs/mitre")


def setup_logging(
    log_file: str,
    error_log_file: str,
    results_log_file: str,
    actions_log_file: str,
    events_log_file: str,
    threats_log_file: str,
    mitre_log_dir: str,
) -> logging.Logger:
    global _MITRE_LOG_DIR
    _MITRE_LOG_DIR = Path(mitre_log_dir)
    _MITRE_LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    app_logger = logging.getLogger(LOGGER_NAME)
    _reset_logger(app_logger)
    app_logger.setLevel(logging.INFO)
    app_logger.addHandler(_build_stream_handler(formatter))
    app_logger.addHandler(_build_file_handler(Path(log_file), logging.INFO, formatter))
    app_logger.addHandler(_build_file_handler(Path(error_log_file), logging.ERROR, formatter))

    _configure_child_logger(RESULTS_LOGGER_NAME, Path(results_log_file), formatter)
    _configure_child_logger(ACTIONS_LOGGER_NAME, Path(actions_log_file), formatter)
    _configure_child_logger(EVENTS_LOGGER_NAME, Path(events_log_file), formatter)
    _configure_child_logger(THREATS_LOGGER_NAME, Path(threats_log_file), formatter)

    mitre_base_logger = logging.getLogger(MITRE_LOGGER_PREFIX)
    _reset_logger(mitre_base_logger)
    mitre_base_logger.setLevel(logging.INFO)
    mitre_base_logger.propagate = False

    _clear_old_mitre_loggers()

    return app_logger


def get_results_logger() -> logging.Logger:
    return logging.getLogger(RESULTS_LOGGER_NAME)


def get_actions_logger() -> logging.Logger:
    return logging.getLogger(ACTIONS_LOGGER_NAME)


def get_events_logger() -> logging.Logger:
    return logging.getLogger(EVENTS_LOGGER_NAME)


def get_threats_logger() -> logging.Logger:
    return logging.getLogger(THREATS_LOGGER_NAME)


def get_mitre_logger(mitre_id: str) -> logging.Logger:
    normalized = mitre_id.lower().replace("/", "_")
    logger_name = f"{MITRE_LOGGER_PREFIX}.{normalized}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    path = _MITRE_LOG_DIR / f"{normalized}.log"
    path.parent.mkdir(parents=True, exist_ok=True)

    if not _logger_has_file_handler(logger, path):
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        logger.addHandler(_build_file_handler(path, logging.INFO, formatter))

    return logger


def _configure_child_logger(name: str, file_path: Path, formatter: logging.Formatter) -> None:
    logger = logging.getLogger(name)
    _reset_logger(logger)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(_build_file_handler(file_path, logging.INFO, formatter))


def _reset_logger(logger: logging.Logger) -> None:
    logger.handlers.clear()
    logger.propagate = False


def _build_stream_handler(formatter: logging.Formatter) -> logging.StreamHandler:
    handler = logging.StreamHandler()
    # Keep console readable; detailed telemetry stays in file logs.
    handler.setLevel(logging.WARNING)
    handler.setFormatter(formatter)
    return handler


def _build_file_handler(
    file_path: Path,
    level: int,
    formatter: logging.Formatter,
) -> logging.FileHandler:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(file_path, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(formatter)
    return handler


def _logger_has_file_handler(logger: logging.Logger, file_path: Path) -> bool:
    expected = str(file_path.resolve())
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler):
            if str(Path(handler.baseFilename).resolve()) == expected:
                return True
    return False


def _clear_old_mitre_loggers() -> None:
    manager = logging.Logger.manager
    for name, obj in manager.loggerDict.items():
        if not isinstance(obj, logging.Logger):
            continue
        if name.startswith(f"{MITRE_LOGGER_PREFIX}."):
            obj.handlers.clear()
            obj.propagate = False
