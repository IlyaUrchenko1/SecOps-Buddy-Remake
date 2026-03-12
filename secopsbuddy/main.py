from __future__ import annotations

from secopsbuddy.cli import parse_args
from secopsbuddy.config import AppConfig, ConfigError, load_config
from secopsbuddy.logging_setup import setup_logging
from secopsbuddy.registry import create_default_registry
from secopsbuddy.runner import DetectionRunner


def _load_config_safely(config_path: str | None) -> AppConfig:
    if config_path is None:
        return load_config(None)
    return load_config(config_path)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        config = _load_config_safely(args.config)
    except ConfigError as exc:
        print(f"[ОШИБКА] Не удалось загрузить конфиг: {exc}")
        return 2

    logger = setup_logging(
        log_file=config.log_file,
        error_log_file=config.log_error_file,
        results_log_file=config.log_results_file,
        actions_log_file=config.log_actions_file,
        events_log_file=config.log_events_file,
        mitre_log_dir=config.mitre_log_dir,
    )

    logger.info("SecOps Buddy запущен")
    logger.info(
        "CLI args: list=%s info=%s run=%s mode=%s config=%s json=%s dry_run=%s continuous=%s monitor_interval_seconds=%s max_cycles=%s",
        args.list,
        args.info,
        args.run,
        args.mode,
        args.config,
        args.json,
        args.dry_run,
        args.continuous,
        args.monitor_interval_seconds,
        args.max_cycles,
    )

    if not args.continuous and args.monitor_interval_seconds is not None:
        print("[ПРИМЕЧАНИЕ] --monitor-interval-seconds используется только с --continuous.")
    if not args.continuous and args.max_cycles is not None:
        print("[ПРИМЕЧАНИЕ] --max-cycles используется только с --continuous.")

    registry = create_default_registry(config=config, logger=logger)

    if args.list:
        detectors = registry.list_detectors()
        if not detectors:
            print("Доступных детекторов нет.")
            return 0

        print("Доступные детекторы:")
        for detector in detectors:
            print(
                f"- {detector.detector_id}: {detector.name} "
                f"({detector.mitre_id})"
            )
        return 0

    if args.info:
        detector = registry.get(args.info)
        if detector is None:
            print(f"[ОШИБКА] Детектор не найден: {args.info}")
            return 2

        print(f"ID детектора : {detector.detector_id}")
        print(f"ID MITRE     : {detector.mitre_id}")
        print(f"Название     : {detector.name}")
        print(f"Описание     : {detector.description}")
        return 0

    runner = DetectionRunner(registry=registry, config=config, logger=logger)
    return runner.run(
        detector_id=args.run,
        mode=args.mode,
        json_output=args.json,
        dry_run_override=True if args.dry_run else None,
        continuous=args.continuous,
        monitor_interval_seconds=args.monitor_interval_seconds,
        max_cycles=args.max_cycles,
    )


if __name__ == "__main__":
    raise SystemExit(main())
