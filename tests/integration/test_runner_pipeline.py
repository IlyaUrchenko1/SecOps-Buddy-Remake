from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.t1030 import T1030Detector
from secopsbuddy.event_dispatcher import EventDispatcher
from secopsbuddy.models import ConnectionRecord
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.runner import DetectionRunner


class CaptureSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class NullLogger:
    def info(self, message: str) -> None:
        return None


def test_integration_runner_with_real_t1030_publishes_pipeline_events(
    monkeypatch,
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    suspicious_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.8,
        min_hits=4,
        min_distinct_local_ports=3,
        alert_cooldown_seconds=120,
    )
    detector = T1030Detector(config=config, collector=collector_factory(suspicious_snapshots))

    registry = DetectorRegistry()
    registry.register(detector)

    runner = DetectionRunner(
        registry=registry,
        config=config,
        logger=logging.getLogger("secopsbuddy.test.integration.runner"),
    )

    capture = CaptureSink()
    runner.event_dispatcher = EventDispatcher([capture])

    monkeypatch.setattr("secopsbuddy.runner.get_mitre_logger", lambda _mitre: NullLogger())

    code = runner.run(detector_id="t1030", mode="monitor", json_output=True, continuous=False)

    assert code == 0

    event_names = [event.get("event") for event in capture.events]
    assert event_names[0] == "detector_started"
    assert "detection_result" in event_names
    assert event_names[-1] == "detector_stopped"

    detection_event = next(event for event in capture.events if event.get("event") == "detection_result")
    assert detection_event["status"] == "suspicious"
    assert detection_event["findings_count"] >= 1
