from __future__ import annotations

import json
import logging
import time
from typing import Any

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.event_dispatcher import EventDispatcher, FileEventSink, LoggerEventSink
from secopsbuddy.logging_setup import (
    get_actions_logger,
    get_events_logger,
    get_mitre_logger,
    get_results_logger,
)
from secopsbuddy.models import DetectionFinding
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.responders.alert import AlertResponder
from secopsbuddy.responders.firewall import FirewallResponder
from secopsbuddy.utils.time_utils import utc_now_iso


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
        self.event_dispatcher = EventDispatcher(
            [
                LoggerEventSink(self.events_logger),
                FileEventSink(self.config.bot_events_file),
            ]
        )
        self._blocked_ips: set[str] = set()
        self._alert_history: dict[str, float] = {}
        self._alert_cooldown_seconds = max(0, int(self.config.alert_cooldown_seconds))

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
        detector = self.registry.get(detector_id)
        if detector is None:
            print(f"[ОШИБКА] Неизвестный detector id: {detector_id}")
            self.logger.error("Неизвестный detector id: %s", detector_id)
            return 2

        self._publish_lifecycle_event(
            event_name="detector_started",
            detector=detector,
            mode=mode,
            continuous=continuous,
        )

        try:
            if continuous:
                interval = (
                    self.config.monitor_loop_interval_seconds
                    if monitor_interval_seconds is None
                    else monitor_interval_seconds
                )
                return self._run_continuous(
                    detector=detector,
                    mode=mode,
                    json_output=json_output,
                    dry_run_override=dry_run_override,
                    monitor_interval_seconds=interval,
                    max_cycles=max_cycles,
                )

            code = self._run_cycle(
                detector=detector,
                mode=mode,
                json_output=json_output,
                dry_run_override=dry_run_override,
                cycle_number=1,
                apply_alert_cooldown=False,
            )
            if not json_output:
                print("Подсказка: для постоянного мониторинга используйте --continuous.")
            return code
        finally:
            self._publish_lifecycle_event(
                event_name="detector_stopped",
                detector=detector,
                mode=mode,
                continuous=continuous,
            )

    def _run_continuous(
        self,
        detector: BaseDetector,
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
            "Старт непрерывного мониторинга: detector=%s mode=%s interval=%s max_cycles=%s cooldown=%s",
            detector.detector_id,
            mode,
            monitor_interval_seconds,
            max_cycles,
            self._alert_cooldown_seconds,
        )

        cycle = 0
        max_exit_code = 0

        try:
            while True:
                cycle += 1
                if not json_output:
                    print(f"\n=== Цикл мониторинга #{cycle} ===")
                code = self._run_cycle(
                    detector=detector,
                    mode=mode,
                    json_output=json_output,
                    dry_run_override=dry_run_override,
                    cycle_number=cycle,
                    apply_alert_cooldown=True,
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
        detector: BaseDetector,
        mode: str,
        json_output: bool,
        dry_run_override: bool | None,
        cycle_number: int,
        apply_alert_cooldown: bool,
    ) -> int:
        self.logger.info(
            "Старт цикла: detector=%s mode=%s cycle=%s dry_run_override=%s",
            detector.detector_id,
            mode,
            cycle_number,
            dry_run_override,
        )

        result = detector.run()
        print(AlertResponder.format_detection_result(result, json_output=json_output))

        self.logger.info(
            "Цикл завершен: detector=%s status=%s score=%.3f findings=%d cycle=%d",
            result.detector_id,
            result.status,
            result.score,
            len(result.findings),
            cycle_number,
        )

        findings_for_alerts, suppressed_count = self._apply_alert_cooldown(
            mitre_id=result.mitre_id,
            findings=result.findings,
            enabled=apply_alert_cooldown,
        )

        if suppressed_count > 0:
            self.logger.info(
                "Cooldown подавил повторные алерты: detector=%s mitre=%s cycle=%s suppressed=%s cooldown=%s",
                result.detector_id,
                result.mitre_id,
                cycle_number,
                suppressed_count,
                self._alert_cooldown_seconds,
            )

        findings_payload = [
            {
                "remote_ip": item.remote_ip,
                "remote_port": item.remote_port,
                "protocol": item.protocol,
                "pid": item.pid,
                "process_name": item.process_name,
                "hit_count": item.hit_count,
                "distinct_local_ports": item.distinct_local_ports,
                "score": item.score,
                "reasons": item.reasons,
            }
            for item in findings_for_alerts
        ]

        event_status = result.status
        event_summary = result.summary
        if result.status == "suspicious" and not findings_for_alerts and suppressed_count > 0:
            event_status = "clean"
            event_summary = (
                f"{result.summary} Повторные алерты подавлены cooldown "
                f"({suppressed_count})."
            )

        result_event = {
            "event": "detection_result",
            "cycle": cycle_number,
            "detector_id": result.detector_id,
            "mitre_id": result.mitre_id,
            "status": event_status,
            "score": result.score,
            "findings_count": len(findings_for_alerts),
            "suppressed_findings_count": suppressed_count,
            "findings": findings_payload,
            "timestamp": result.timestamp,
            "summary": event_summary,
            "mode": mode,
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
                    "detector_id": result.detector_id,
                    "mitre_id": result.mitre_id,
                    "ip": action.ip,
                    "blocked": action.blocked,
                    "backend": action.backend,
                    "command": action.command,
                    "message": action.message,
                    "timestamp": utc_now_iso(),
                }
                self.actions_logger.info(json.dumps(action_event, ensure_ascii=False))
                self.event_dispatcher.publish(action_event)
                if action.blocked:
                    self._blocked_ips.add(action.ip)
                    mitigated_event = {
                        "event": "threat_mitigated",
                        "cycle": cycle_number,
                        "detector_id": result.detector_id,
                        "mitre_id": result.mitre_id,
                        "ip": action.ip,
                        "timestamp": utc_now_iso(),
                        "message": "Подозрительный IP был заблокирован.",
                    }
                    self.event_dispatcher.publish(mitigated_event)

        if result.status == "error":
            return 1
        return 0

    def _apply_alert_cooldown(
        self,
        mitre_id: str,
        findings: list[DetectionFinding],
        enabled: bool,
    ) -> tuple[list[DetectionFinding], int]:
        if not findings or not enabled or self._alert_cooldown_seconds <= 0:
            return findings, 0

        now_ts = time.time()
        self._prune_alert_history(now_ts)

        filtered: list[DetectionFinding] = []
        suppressed = 0

        for finding in findings:
            fingerprint = self._build_alert_fingerprint(mitre_id, finding)
            last_ts = self._alert_history.get(fingerprint)
            if last_ts is not None and (now_ts - last_ts) < self._alert_cooldown_seconds:
                suppressed += 1
                continue

            self._alert_history[fingerprint] = now_ts
            filtered.append(finding)

        return filtered, suppressed

    def _build_alert_fingerprint(self, mitre_id: str, finding: DetectionFinding) -> str:
        process_name = (finding.process_name or "-").lower()
        remote_port = finding.remote_port if finding.remote_port is not None else "-"
        return f"{mitre_id}:{finding.remote_ip}:{remote_port}:{process_name}"

    def _prune_alert_history(self, now_ts: float) -> None:
        if not self._alert_history:
            return

        ttl = max(self._alert_cooldown_seconds * 10, self._alert_cooldown_seconds + 1)
        stale = [
            fingerprint
            for fingerprint, ts in self._alert_history.items()
            if (now_ts - ts) > ttl
        ]
        for fingerprint in stale:
            self._alert_history.pop(fingerprint, None)

    def _publish_lifecycle_event(
        self,
        event_name: str,
        detector: BaseDetector,
        mode: str,
        continuous: bool,
    ) -> None:
        event: dict[str, Any] = {
            "event": event_name,
            "detector_id": detector.detector_id,
            "mitre_id": detector.mitre_id,
            "mode": mode,
            "continuous": continuous,
            "timestamp": utc_now_iso(),
        }
        self.event_dispatcher.publish(event)
