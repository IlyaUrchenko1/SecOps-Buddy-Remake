from __future__ import annotations

import json
import logging
import time

from secopsbuddy.config import AppConfig
from secopsbuddy.event_dispatcher import EventDispatcher, LoggerEventSink
from secopsbuddy.logging_setup import (
    get_actions_logger,
    get_events_logger,
    get_mitre_logger,
    get_results_logger,
)
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.responders.alert import AlertResponder
from secopsbuddy.responders.firewall import FirewallResponder


class DetectionRunner:
    def __init__(
        self,
        registry: DetectorRegistry,
        config: AppConfig,
        logger: logging.Logger,
    ) -> None:
        self.registry = registry
        self.config = config
        self.logger = logger
        self.results_logger = get_results_logger()
        self.actions_logger = get_actions_logger()
        self.events_logger = get_events_logger()
        self.event_dispatcher = EventDispatcher([LoggerEventSink(self.events_logger)])
        self._blocked_ips: set[str] = set()

    def run(
        self,
        detector_id: str,
        mode: str = "monitor",
        json_output: bool = False,
        dry_run_override: bool | None = None,
        continuous: bool = False,
        monitor_interval_seconds: float | None = None,
        max_cycles: int | None = None,
    ) -> int:
        if continuous:
            interval = (
                self.config.monitor_loop_interval_seconds
                if monitor_interval_seconds is None
                else monitor_interval_seconds
            )
            return self._run_continuous(
                detector_id=detector_id,
                mode=mode,
                json_output=json_output,
                dry_run_override=dry_run_override,
                monitor_interval_seconds=interval,
                max_cycles=max_cycles,
            )

        code = self._run_cycle(
            detector_id=detector_id,
            mode=mode,
            json_output=json_output,
            dry_run_override=dry_run_override,
            cycle_number=1,
        )
        if not json_output:
            print("Подсказка: для постоянного мониторинга используйте --continuous.")
        return code

    def _run_continuous(
        self,
        detector_id: str,
        mode: str,
        json_output: bool,
        dry_run_override: bool | None,
        monitor_interval_seconds: float,
        max_cycles: int | None,
    ) -> int:
        if monitor_interval_seconds < 0:
            print("[ОШИБКА] monitor_interval_seconds должен быть >= 0")
            return 2
        if max_cycles is not None and max_cycles <= 0:
            print("[ОШИБКА] max_cycles должен быть > 0")
            return 2

        print(
            "Запущен непрерывный мониторинг. "
            "Нажмите Ctrl+C для остановки."
        )
        self.logger.info(
            "Старт непрерывного мониторинга: detector=%s mode=%s interval=%s max_cycles=%s",
            detector_id,
            mode,
            monitor_interval_seconds,
            max_cycles,
        )

        cycle = 0
        max_exit_code = 0

        try:
            while True:
                cycle += 1
                if not json_output:
                    print(f"\n=== Цикл мониторинга #{cycle} ===")
                code = self._run_cycle(
                    detector_id=detector_id,
                    mode=mode,
                    json_output=json_output,
                    dry_run_override=dry_run_override,
                    cycle_number=cycle,
                )
                max_exit_code = max(max_exit_code, code)

                if max_cycles is not None and cycle >= max_cycles:
                    self.logger.info("Достигнут лимит циклов: %s", max_cycles)
                    print(f"Мониторинг завершен: достигнут лимит циклов ({max_cycles}).")
                    break

                if monitor_interval_seconds > 0:
                    time.sleep(monitor_interval_seconds)
        except KeyboardInterrupt:
            self.logger.info("Мониторинг остановлен пользователем")
            print("Мониторинг остановлен пользователем.")

        return max_exit_code

    def _run_cycle(
        self,
        detector_id: str,
        mode: str,
        json_output: bool,
        dry_run_override: bool | None,
        cycle_number: int,
    ) -> int:
        detector = self.registry.get(detector_id)
        if detector is None:
            print(f"[ОШИБКА] Неизвестный detector id: {detector_id}")
            self.logger.error("Неизвестный detector id: %s", detector_id)
            return 2

        self.logger.info(
            "Старт цикла: detector=%s mode=%s cycle=%s dry_run_override=%s",
            detector_id,
            mode,
            cycle_number,
            dry_run_override,
        )

        result = detector.run()
        print(AlertResponder.format_detection_result(result, json_output=json_output))

        self.logger.info(
            "Цикл завершен: detector=%s status=%s score=%.3f findings=%d cycle=%d",
            detector_id,
            result.status,
            result.score,
            len(result.findings),
            cycle_number,
        )

        result_event = {
            "event": "detection_result",
            "cycle": cycle_number,
            "detector_id": result.detector_id,
            "mitre_id": result.mitre_id,
            "status": result.status,
            "score": result.score,
            "findings_count": len(result.findings),
            "timestamp": result.timestamp,
            "summary": result.summary,
        }
        self.results_logger.info(json.dumps(result_event, ensure_ascii=False))
        self.event_dispatcher.publish(result_event)

        mitre_logger = get_mitre_logger(result.mitre_id)
        mitre_logger.info(json.dumps(result.to_dict(), ensure_ascii=False))

        if mode == "block" and result.status == "suspicious" and result.findings:
            dry_run = self.config.dry_run if dry_run_override is None else dry_run_override
            responder = FirewallResponder(
                dry_run=dry_run,
                block_private_ips=self.config.block_private_ips,
                logger=self.logger,
            )

            ips_to_block = [
                finding.remote_ip
                for finding in result.findings
                if finding.remote_ip not in self._blocked_ips
            ]
            actions = responder.block_ips(ips_to_block)
            print(AlertResponder.format_firewall_actions(actions))

            for action in actions:
                action_event = {
                    "event": "firewall_action",
                    "cycle": cycle_number,
                    "ip": action.ip,
                    "blocked": action.blocked,
                    "backend": action.backend,
                    "command": action.command,
                    "message": action.message,
                }
                self.actions_logger.info(json.dumps(action_event, ensure_ascii=False))
                self.event_dispatcher.publish(action_event)
                if action.blocked:
                    self._blocked_ips.add(action.ip)

        if result.status == "error":
            return 1
        return 0
