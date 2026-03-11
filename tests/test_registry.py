from secopsbuddy.config import AppConfig
from secopsbuddy.registry import create_default_registry


def test_default_registry_contains_t1030() -> None:
    registry = create_default_registry(AppConfig())
    detectors = registry.list_detectors()

    assert detectors
    assert any(item.detector_id == "t1030" for item in detectors)


def test_registry_get_returns_detector_or_none() -> None:
    registry = create_default_registry(AppConfig())

    detector = registry.get("t1030")
    assert detector is not None
    assert detector.mitre_id == "T1030"

    assert registry.get("unknown-detector") is None
