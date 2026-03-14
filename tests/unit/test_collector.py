from __future__ import annotations

import logging
import subprocess
from unittest.mock import Mock

import pytest

from secopsbuddy.collectors.network_snapshot import CollectorError, NetworkSnapshotCollector, is_routable_ip


def test_parse_ss_line_extracts_connection_fields() -> None:
    collector = NetworkSnapshotCollector(command_preference=["ss_tunp"])

    line = (
        "tcp ESTAB 0 0 10.0.0.10:45678 93.184.216.34:443 "
        "users:((\"python\",pid=1234,fd=5))"
    )

    record = collector._parse_ss_line(line, timestamp="2026-03-14T00:00:00Z")

    assert record is not None
    assert record.proto == "tcp"
    assert record.state == "ESTAB"
    assert record.local_ip == "10.0.0.10"
    assert record.local_port == 45678
    assert record.remote_ip == "93.184.216.34"
    assert record.remote_port == 443
    assert record.process_name == "python"
    assert record.pid == 1234


def test_parse_netstat_line_extracts_connection_fields() -> None:
    collector = NetworkSnapshotCollector(command_preference=["netstat_tunp"])

    line = "tcp 0 0 10.0.0.10:45678 93.184.216.34:443 ESTABLISHED 1234/python"
    record = collector._parse_netstat_line(line, timestamp="2026-03-14T00:00:00Z")

    assert record is not None
    assert record.proto == "tcp"
    assert record.state == "ESTABLISHED"
    assert record.local_port == 45678
    assert record.remote_port == 443
    assert record.process_name == "python"
    assert record.pid == 1234


def test_parse_address_port_supports_ipv6_and_interface_suffix() -> None:
    ip_value, port = NetworkSnapshotCollector._parse_address_port("[fe80::1%eth0]:5353")

    assert ip_value == "fe80::1"
    assert port == 5353


def test_collect_snapshot_uses_available_command(monkeypatch) -> None:
    collector = NetworkSnapshotCollector(command_preference=["ss_tunp"])

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.shutil.which", lambda _name: "/usr/bin/ss")

    def _fake_run(command: list[str], capture_output: bool, text: bool, check: bool):
        assert command[0] == "ss"
        assert capture_output is True
        assert text is True
        assert check is True
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=(
                "tcp ESTAB 0 0 10.0.0.10:45678 93.184.216.34:443 "
                "users:((\"python\",pid=1234,fd=5))\n"
            ),
            stderr="",
        )

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.subprocess.run", _fake_run)

    snapshot = collector.collect_snapshot()

    assert len(snapshot) == 1
    assert snapshot[0].process_name == "python"


def test_collect_snapshot_falls_back_to_next_command_on_failure(monkeypatch) -> None:
    collector = NetworkSnapshotCollector(command_preference=["ss_tunp", "netstat_tunp"])

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.shutil.which", lambda _name: "/usr/bin/tool")

    state = {"count": 0}

    def _fake_run(command: list[str], capture_output: bool, text: bool, check: bool):
        state["count"] += 1
        if state["count"] == 1:
            raise subprocess.CalledProcessError(returncode=1, cmd=command, stderr="boom")
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="tcp 0 0 10.0.0.10:45678 93.184.216.34:443 ESTABLISHED 1234/python\n",
            stderr="",
        )

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.subprocess.run", _fake_run)

    snapshot = collector.collect_snapshot()

    assert len(snapshot) == 1
    assert snapshot[0].process_name == "python"
    assert state["count"] == 2


def test_collect_snapshot_raises_when_no_commands_available(monkeypatch) -> None:
    collector = NetworkSnapshotCollector(command_preference=["ss_tunp", "netstat_tunp"])

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.shutil.which", lambda _name: None)

    with pytest.raises(CollectorError):
        collector.collect_snapshot()


def test_collect_series_respects_snapshot_count_and_sleep(monkeypatch) -> None:
    collector = NetworkSnapshotCollector(command_preference=["ss_tunp"])

    monkeypatch.setattr(collector, "collect_snapshot", lambda: [])
    sleep_mock = Mock()
    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.time.sleep", sleep_mock)

    snapshots = collector.collect_series(snapshot_count=3, snapshot_interval_seconds=0.5)

    assert len(snapshots) == 3
    assert sleep_mock.call_count == 2


def test_is_routable_ip_filters_non_routable_values() -> None:
    assert is_routable_ip("8.8.8.8") is True
    assert is_routable_ip("127.0.0.1") is False
    assert is_routable_ip("::1") is False
    assert is_routable_ip(None) is False
    assert is_routable_ip("not-an-ip") is False
