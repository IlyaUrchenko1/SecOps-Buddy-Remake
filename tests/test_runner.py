from __future__ import annotations

import logging
from typing import Any
from unittest.mock import Mock

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.event_dispatcher import EventDispatcher
from secopsbuddy.models import DetectionFinding, DetectionResult
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.runner import DetectionRunner


class FakeDetector(BaseDetector):
    def __init__(self, results: list[DetectionResult]) -> None:
        self._results = results
        self._index = 0

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
        return "Fake detector for internal runner tests"

    def run(self) -> DetectionResult:
        if self._index >= len(self._results):
            return self._results[-1]
        result = self._results[self._index]
        self._index += 1
        return result


class CaptureSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class NullLogger:
    def info(self, message: str) -> None:
        return None


def _suspicious_result() -> DetectionResult:
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


def test_runner_run_executes_single_cycle_and_lifecycle_events(monkeypatch) -> None:
    registry = DetectorRegistry()
    registry.register(FakeDetector([_suspicious_result()]))

    runner = DetectionRunner(
        registry=registry,
        config=AppConfig(alert_cooldown_seconds=120),
        logger=logging.getLogger("secopsbuddy.test.runner"),
    )

    capture = CaptureSink()
    runner.event_dispatcher = EventDispatcher([capture])

    run_cycle_mock = Mock(return_value=0)
    monkeypatch.setattr(runner, "_run_cycle", run_cycle_mock)

    code = runner.run(detector_id="fake", mode="monitor", json_output=True, continuous=False)

    assert code == 0
    run_cycle_mock.assert_called_once()
    kwargs = run_cycle_mock.call_args.kwargs
    assert kwargs["cycle_number"] == 1
    assert kwargs["apply_alert_cooldown"] is False

    lifecycle_events = [event["event"] for event in capture.events]
    assert lifecycle_events == ["detector_started", "detector_stopped"]


def test_runner_run_cycle_publishes_detection_result_event(monkeypatch) -> None:
    registry = DetectorRegistry()
    detector = FakeDetector([_suspicious_result()])
    registry.register(detector)

    runner = DetectionRunner(
        registry=registry,
        config=AppConfig(alert_cooldown_seconds=120),
        logger=logging.getLogger("secopsbuddy.test.runner"),
    )
    capture = CaptureSink()
    runner.event_dispatcher = EventDispatcher([capture])

    monkeypatch.setattr("secopsbuddy.runner.get_mitre_logger", lambda _mitre: NullLogger())

    code = runner._run_cycle(
        detector=detector,
        mode="monitor",
        json_output=True,
        dry_run_override=None,
        cycle_number=1,
        apply_alert_cooldown=False,
    )

    assert code == 0

    detection_events = [
        event for event in capture.events if event.get("event") == "detection_result"
    ]
    assert len(detection_events) == 1

    event = detection_events[0]
    assert event["status"] == "suspicious"
    assert event["findings_count"] == 1
    assert event["suppressed_findings_count"] == 0
    assert event["mitre_id"] == "T9999"


def test_runner_suppresses_duplicate_alerts_with_cooldown(monkeypatch) -> None:
    result = _suspicious_result()
    registry = DetectorRegistry()
    detector = FakeDetector([result, result])
    registry.register(detector)

    runner = DetectionRunner(
        registry=registry,
        config=AppConfig(alert_cooldown_seconds=120),
        logger=logging.getLogger("secopsbuddy.test.runner"),
    )
    capture = CaptureSink()
    runner.event_dispatcher = EventDispatcher([capture])

    monkeypatch.setattr("secopsbuddy.runner.get_mitre_logger", lambda _mitre: NullLogger())

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
        event for event in capture.events if event.get("event") == "detection_result"
    ]

    assert len(detection_events) == 2
    assert detection_events[0]["status"] == "suspicious"
    assert detection_events[0]["findings_count"] == 1
    assert detection_events[1]["status"] == "clean"
    assert detection_events[1]["findings_count"] == 0
    assert detection_events[1]["suppressed_findings_count"] == 1
