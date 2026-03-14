from __future__ import annotations

import logging
from typing import Any

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.event_dispatcher import EventDispatcher
from secopsbuddy.models import DetectionFinding, DetectionResult
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.responders.firewall import FirewallAction
from secopsbuddy.runner import DetectionRunner


class FakeDetector(BaseDetector):
    @property
    def detector_id(self) -> str:
        return "fake"

    @property
    def mitre_id(self) -> str:
        return "T9999"

    @property
    def name(self) -> str:
        return "Fake Detector"

    @property
    def description(self) -> str:
        return "Integration fake detector"

    def run(self) -> DetectionResult:
        return DetectionResult(
            detector_id="fake",
            mitre_id="T9999",
            detector_name="Fake Detector",
            status="suspicious",
            score=0.9,
            findings=[
                DetectionFinding(
                    remote_ip="8.8.8.8",
                    remote_port=443,
                    protocol="tcp",
                    pid=100,
                    process_name="python",
                    hit_count=8,
                    distinct_local_ports=6,
                    score=0.9,
                    reasons=["test"],
                )
            ],
            summary="suspicious",
            timestamp="2026-03-14T00:00:00Z",
        )


class CaptureSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class NullLogger:
    def info(self, message: str) -> None:
        return None


def test_integration_runner_block_mode_publishes_firewall_and_mitigation_events(monkeypatch) -> None:
    detector = FakeDetector()
    registry = DetectorRegistry()
    registry.register(detector)

    runner = DetectionRunner(
        registry=registry,
        config=AppConfig(dry_run=False),
        logger=logging.getLogger("secopsbuddy.test.integration.block"),
    )

    capture = CaptureSink()
    runner.event_dispatcher = EventDispatcher([capture])

    called_ips: list[str] = []

    def _fake_block_ips(self, ips: list[str]) -> list[FirewallAction]:
        called_ips.extend(ips)
        return [
            FirewallAction(
                ip="8.8.8.8",
                blocked=True,
                message="blocked",
                backend="ufw",
                command="ufw deny out to 8.8.8.8",
            )
        ]

    monkeypatch.setattr("secopsbuddy.runner.FirewallResponder.block_ips", _fake_block_ips)
    monkeypatch.setattr("secopsbuddy.runner.get_mitre_logger", lambda _mitre: NullLogger())

    code = runner._run_cycle(
        detector=detector,
        mode="block",
        json_output=True,
        dry_run_override=False,
        cycle_number=1,
        apply_alert_cooldown=False,
    )

    assert code == 0
    assert called_ips == ["8.8.8.8"]

    event_names = [event.get("event") for event in capture.events]
    assert "detection_result" in event_names
    assert "firewall_action" in event_names
    assert "threat_mitigated" in event_names
