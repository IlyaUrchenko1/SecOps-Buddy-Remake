from __future__ import annotations

from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.t1030 import T1030Detector
from secopsbuddy.models import ConnectionRecord


class FakeCollector:
    def __init__(self, snapshots: list[list[ConnectionRecord]]) -> None:
        self.snapshots = snapshots

    def collect_series(
        self,
        snapshot_count: int,
        snapshot_interval_seconds: float,
    ) -> list[list[ConnectionRecord]]:
        return self.snapshots[:snapshot_count]


def _record(ts_index: int, local_port: int, remote_ip: str) -> ConnectionRecord:
    return ConnectionRecord(
        timestamp=f"2026-01-01T00:00:{ts_index:02d}Z",
        proto="tcp",
        state="ESTAB",
        local_ip="10.0.0.10",
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=443,
        pid=4321,
        process_name="python",
    )


def test_t1030_detector_flags_repeated_outbound_pattern() -> None:
    snapshots: list[list[ConnectionRecord]] = []
    for index in range(6):
        snapshots.append([
            _record(index, 45000 + index, "93.184.216.34"),
            _record(index, 52000 + index, "93.184.216.34"),
        ])

    config = AppConfig(
        snapshot_count=6,
        snapshot_interval_seconds=0.0,
        suspicion_threshold=0.55,
        min_hits=4,
        min_distinct_local_ports=3,
    )
    detector = T1030Detector(config=config, collector=FakeCollector(snapshots))

    result = detector.run()

    assert result.status == "suspicious"
    assert result.findings
    assert result.score >= config.suspicion_threshold
    assert any(f.remote_ip == "93.184.216.34" for f in result.findings)


def test_t1030_detector_clean_when_no_candidates() -> None:
    snapshots = [
        [
            ConnectionRecord(
                timestamp="2026-01-01T00:00:00Z",
                proto="tcp",
                state="LISTEN",
                local_ip="0.0.0.0",
                local_port=22,
                remote_ip="0.0.0.0",
                remote_port=None,
                pid=1,
                process_name="sshd",
            )
        ]
    ]

    config = AppConfig(snapshot_count=1, snapshot_interval_seconds=0.0)
    detector = T1030Detector(config=config, collector=FakeCollector(snapshots))

    result = detector.run()

    assert result.status == "clean"
    assert result.findings == []
