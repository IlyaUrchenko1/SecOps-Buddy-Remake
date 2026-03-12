from __future__ import annotations

import logging
from typing import Any

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.event_dispatcher import EventDispatcher
from secopsbuddy.models import DetectionFinding, DetectionResult
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.runner import DetectionRunner


class FakeDetector(BaseDetector):
    def __init__(self, result: DetectionResult) -> None:
        self._result = result

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
        return "Fake detector for cooldown tests"

    def run(self) -> DetectionResult:
        return self._result


class CaptureSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def _build_result() -> DetectionResult:
    finding = DetectionFinding(
        remote_ip="93.184.216.34",
        remote_port=443,
        protocol="tcp",
        pid=1234,
        process_name="python",
        hit_count=8,
        distinct_local_ports=6,
        score=0.92,
        reasons=["test"],
    )
    return DetectionResult(
        detector_id="fake",
        mitre_id="T9999",
        detector_name="Fake Detector",
        status="suspicious",
        score=0.92,
        findings=[finding],
        summary="Fake suspicious activity",
        timestamp="2026-03-12T00:00:00Z",
    )


def test_runner_suppresses_duplicate_alerts_in_cooldown() -> None:
    config = AppConfig(alert_cooldown_seconds=120)
    registry = DetectorRegistry()
    detector = FakeDetector(_build_result())
    registry.register(detector)

    logger = logging.getLogger("secopsbuddy.test.runner")
    runner = DetectionRunner(registry=registry, config=config, logger=logger)

    sink = CaptureSink()
    runner.event_dispatcher = EventDispatcher([sink])

    runner._run_cycle(
        detector=detector,
        mode="monitor",
        json_output=True,
        dry_run_override=None,
        cycle_number=1,
        apply_alert_cooldown=True,
    )
    runner._run_cycle(
        detector=detector,
        mode="monitor",
        json_output=True,
        dry_run_override=None,
        cycle_number=2,
        apply_alert_cooldown=True,
    )

    detection_events = [
        event for event in sink.events if event.get("event") == "detection_result"
    ]

    assert len(detection_events) == 2
    assert detection_events[0]["status"] == "suspicious"
    assert detection_events[0]["findings_count"] == 1

    assert detection_events[1]["status"] == "clean"
    assert detection_events[1]["findings_count"] == 0
    assert detection_events[1]["suppressed_findings_count"] == 1
