from __future__ import annotations

import logging
from dataclasses import dataclass

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.detectors.t1030 import T1030Detector


@dataclass(slots=True)
class DetectorSummary:
    detector_id: str
    mitre_id: str
    name: str
    description: str


class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        self._detectors[detector.detector_id] = detector

    def list_detectors(self) -> list[DetectorSummary]:
        return [
            DetectorSummary(
                detector_id=item.detector_id,
                mitre_id=item.mitre_id,
                name=item.name,
                description=item.description,
            )
            for item in self._detectors.values()
        ]

    def get(self, detector_id: str) -> BaseDetector | None:
        return self._detectors.get(detector_id)


def create_default_registry(
    config: AppConfig,
    logger: logging.Logger | None = None,
) -> DetectorRegistry:
    registry = DetectorRegistry()
    detector_logger = logger.getChild("detector.t1030") if logger else None
    registry.register(T1030Detector(config=config, logger=detector_logger))
    return registry
