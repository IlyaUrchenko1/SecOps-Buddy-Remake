from __future__ import annotations

from abc import ABC, abstractmethod

from secopsbuddy.models import DetectionResult


class BaseDetector(ABC):
    @property
    @abstractmethod
    def detector_id(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def mitre_id(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def run(self) -> DetectionResult:
        raise NotImplementedError
