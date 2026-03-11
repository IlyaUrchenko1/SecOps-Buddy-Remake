from __future__ import annotations

import logging

from secopsbuddy.config import AppConfig
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

    def run(
        self,
        detector_id: str,
        mode: str = "monitor",
        json_output: bool = False,
        dry_run_override: bool | None = None,
    ) -> int:
        detector = self.registry.get(detector_id)
        if detector is None:
            print(f"[ОШИБКА] Неизвестный detector id: {detector_id}")
            self.logger.error("Неизвестный detector id: %s", detector_id)
            return 2

        self.logger.info(
            "Старт детектирования: detector=%s mode=%s dry_run_override=%s",
            detector_id,
            mode,
            dry_run_override,
        )

        result = detector.run()
        print(AlertResponder.format_detection_result(result, json_output=json_output))

        self.logger.info(
            "Детектирование завершено: detector=%s status=%s score=%.3f findings=%d",
            detector_id,
            result.status,
            result.score,
            len(result.findings),
        )

        if mode == "block" and result.status == "suspicious" and result.findings:
            dry_run = self.config.dry_run if dry_run_override is None else dry_run_override
            responder = FirewallResponder(
                dry_run=dry_run,
                block_private_ips=self.config.block_private_ips,
                logger=self.logger,
            )
            ips_to_block = [finding.remote_ip for finding in result.findings]
            actions = responder.block_ips(ips_to_block)
            print(AlertResponder.format_firewall_actions(actions))

        if result.status == "error":
            return 1
        return 0
