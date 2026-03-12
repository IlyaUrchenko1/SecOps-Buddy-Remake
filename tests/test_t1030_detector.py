from __future__ import annotations

from collections.abc import Callable

import pytest

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.t1030 import T1030Detector
from secopsbuddy.models import ConnectionRecord


def test_t1030_detector_detects_repeated_suspicious_connections(
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    suspicious_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.8,
        min_hits=4,
        min_distinct_local_ports=3,
    )
    detector = T1030Detector(config=config, collector=collector_factory(suspicious_snapshots))

    result = detector.run()

    assert result.status == "suspicious"
    assert len(result.findings) == 1

    finding = result.findings[0]
    assert finding.remote_ip == "93.184.216.34"
    assert finding.hit_count == 6
    assert finding.distinct_local_ports == 6
    assert finding.score >= config.suspicion_threshold


def test_t1030_detector_scoring_matches_expected_behavior(
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    suspicious_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.0,
        min_hits=4,
        min_distinct_local_ports=3,
    )
    detector = T1030Detector(config=config, collector=collector_factory(suspicious_snapshots))

    result = detector.run()

    assert result.status == "suspicious"
    assert result.score == pytest.approx(0.98, rel=1e-3)
    assert result.findings[0].score == pytest.approx(0.98, rel=1e-3)


def test_t1030_detector_respects_allowlist(
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    suspicious_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.8,
        min_hits=4,
        min_distinct_local_ports=3,
        allowed_remote_ips=["93.184.216.34"],
    )
    detector = T1030Detector(config=config, collector=collector_factory(suspicious_snapshots))

    result = detector.run()

    assert result.status == "clean"
    assert result.findings == []


def test_t1030_detector_respects_suppressed_local_ports(
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    suspicious_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.8,
        min_hits=4,
        min_distinct_local_ports=3,
        suppressed_ports=[45000, 45001, 45002, 45003, 45004, 45005],
    )
    detector = T1030Detector(config=config, collector=collector_factory(suspicious_snapshots))

    result = detector.run()

    assert result.status == "clean"
    assert result.findings == []


def test_t1030_detector_ignores_safe_or_non_outbound_connections(
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    safe_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(snapshot_count=1, snapshot_interval_seconds=0.0)
    detector = T1030Detector(config=config, collector=collector_factory(safe_snapshots))

    result = detector.run()

    assert result.status == "clean"
    assert result.findings == []


def test_t1030_detector_lowers_score_for_private_destination(
    collector_factory: Callable[[list[list[ConnectionRecord]]], object],
    private_noisy_snapshots: list[list[ConnectionRecord]],
) -> None:
    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.8,
        min_hits=4,
        min_distinct_local_ports=3,
    )
    detector = T1030Detector(config=config, collector=collector_factory(private_noisy_snapshots))

    result = detector.run()

    assert result.status == "clean"
    assert result.score < config.suspicion_threshold
