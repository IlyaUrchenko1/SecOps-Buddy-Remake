from __future__ import annotations

from collections.abc import Callable

import pytest

from secopsbuddy.models import ConnectionRecord


class FakeCollector:
    def __init__(self, snapshots: list[list[ConnectionRecord]]) -> None:
        self._snapshots = snapshots

    def collect_series(
        self,
        snapshot_count: int,
        snapshot_interval_seconds: float,
    ) -> list[list[ConnectionRecord]]:
        return self._snapshots[:snapshot_count]


@pytest.fixture
def connection_factory() -> Callable[..., ConnectionRecord]:
    def _build(**overrides: object) -> ConnectionRecord:
        base = {
            "timestamp": "2026-01-01T00:00:00Z",
            "proto": "tcp",
            "state": "ESTAB",
            "local_ip": "10.0.0.10",
            "local_port": 45000,
            "remote_ip": "93.184.216.34",
            "remote_port": 443,
            "pid": 4321,
            "process_name": "python",
        }
        base.update(overrides)
        return ConnectionRecord(**base)

    return _build


@pytest.fixture
def collector_factory() -> Callable[[list[list[ConnectionRecord]]], FakeCollector]:
    def _build(snapshots: list[list[ConnectionRecord]]) -> FakeCollector:
        return FakeCollector(snapshots)

    return _build


@pytest.fixture
def suspicious_snapshots(
    connection_factory: Callable[..., ConnectionRecord],
) -> list[list[ConnectionRecord]]:
    snapshots: list[list[ConnectionRecord]] = []
    for index in range(6):
        snapshots.append(
            [
                connection_factory(
                    timestamp=f"2026-01-01T00:00:{index:02d}Z",
                    local_port=45000 + index,
                    remote_ip="93.184.216.34",
                    remote_port=443,
                    process_name="python",
                )
            ]
        )
    return snapshots


@pytest.fixture
def private_noisy_snapshots(
    connection_factory: Callable[..., ConnectionRecord],
) -> list[list[ConnectionRecord]]:
    snapshots: list[list[ConnectionRecord]] = []
    for index in range(6):
        snapshots.append(
            [
                connection_factory(
                    timestamp=f"2026-01-01T00:01:{index:02d}Z",
                    local_port=46000 + index,
                    remote_ip="10.10.10.50",
                    remote_port=443,
                    process_name="python",
                )
            ]
        )
    return snapshots


@pytest.fixture
def safe_snapshots(
    connection_factory: Callable[..., ConnectionRecord],
) -> list[list[ConnectionRecord]]:
    return [
        [
            connection_factory(
                state="LISTEN",
                local_ip="0.0.0.0",
                local_port=22,
                remote_ip="0.0.0.0",
                remote_port=None,
                process_name="sshd",
            ),
            connection_factory(
                state="ESTAB",
                remote_ip=None,
                remote_port=None,
                process_name="systemd",
            ),
        ]
    ]
