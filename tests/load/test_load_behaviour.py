from __future__ import annotations

import logging

import pytest

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.event_dispatcher import EventDispatcher
from secopsbuddy.models import DetectionFinding, DetectionResult
from secopsbuddy.registry import DetectorRegistry
from secopsbuddy.runner import DetectionRunner


class CaptureSink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)


class FakeDetector(BaseDetector):
    @property
    def detector_id(self) -> str:
        return "load"

    @property
    def mitre_id(self) -> str:
        return "TLOAD"

    @property
    def name(self) -> str:
        return "Load Detector"

    @property
    def description(self) -> str:
        return "Synthetic detector for load-like tests"

    def run(self) -> DetectionResult:
        return DetectionResult(
            detector_id="load",
            mitre_id="TLOAD",
            detector_name="Load Detector",
            status="suspicious",
            score=0.9,
            findings=[
                DetectionFinding(
                    remote_ip="93.184.216.34",
                    remote_port=443,
                    protocol="tcp",
                    pid=1,
                    process_name="python",
                    hit_count=10,
                    distinct_local_ports=10,
                    score=0.9,
                    reasons=["load"],
                )
            ],
            summary="load result",
            timestamp="2026-03-14T00:00:00Z",
        )


@pytest.mark.load
def test_load_dispatcher_publishes_many_events() -> None:
    sink = CaptureSink()
    dispatcher = EventDispatcher([sink])

    for idx in range(10_000):
        dispatcher.publish({"event": "load_event", "idx": idx})

    assert len(sink.events) == 10_000
    assert sink.events[0]["idx"] == 0
    assert sink.events[-1]["idx"] == 9_999


@pytest.mark.load
def test_load_runner_cooldown_handles_many_findings() -> None:
    registry = DetectorRegistry()
    registry.register(FakeDetector())

    runner = DetectionRunner(
        registry=registry,
        config=AppConfig(alert_cooldown_seconds=120),
        logger=logging.getLogger("secopsbuddy.test.load"),
    )

    findings = [
        DetectionFinding(
            remote_ip=f"203.0.113.{idx % 200}",
            remote_port=443,
            protocol="tcp",
            pid=idx,
            process_name="python",
            hit_count=5,
            distinct_local_ports=5,
            score=0.8,
            reasons=[],
        )
        for idx in range(5_000)
    ]

    filtered_first, suppressed_first = runner._apply_alert_cooldown(
        mitre_id="TLOAD",
        findings=findings,
        enabled=True,
    )

    filtered_second, suppressed_second = runner._apply_alert_cooldown(
        mitre_id="TLOAD",
        findings=findings,
        enabled=True,
    )

    assert len(filtered_first) == 200
    assert suppressed_first == 4_800
    assert len(filtered_second) == 0
    assert suppressed_second == 5_000
