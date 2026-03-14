from __future__ import annotations

import pytest

from secopsbuddy.cli import parse_args
from secopsbuddy.models import DetectionFinding, DetectionResult


def test_cli_parse_run_arguments() -> None:
    args = parse_args(
        [
            "--run",
            "t1030",
            "--mode",
            "block",
            "--continuous",
            "--monitor-interval-seconds",
            "10",
            "--max-cycles",
            "5",
            "--json",
            "--dry-run",
        ]
    )

    assert args.run == "t1030"
    assert args.mode == "block"
    assert args.continuous is True
    assert args.monitor_interval_seconds == 10.0
    assert args.max_cycles == 5
    assert args.json is True
    assert args.dry_run is True


def test_cli_requires_exactly_one_action() -> None:
    with pytest.raises(SystemExit):
        parse_args([])

    with pytest.raises(SystemExit):
        parse_args(["--list", "--run", "t1030"])


def test_detection_result_to_dict_contains_nested_findings() -> None:
    result = DetectionResult(
        detector_id="t1030",
        mitre_id="T1030",
        detector_name="Test Detector",
        status="suspicious",
        score=0.91,
        findings=[
            DetectionFinding(
                remote_ip="93.184.216.34",
                remote_port=443,
                protocol="tcp",
                pid=42,
                process_name="python",
                hit_count=8,
                distinct_local_ports=6,
                score=0.91,
                reasons=["test reason"],
            )
        ],
        summary="summary",
        timestamp="2026-03-14T12:00:00Z",
    )

    payload = result.to_dict()

    assert payload["detector_id"] == "t1030"
    assert payload["findings"][0]["remote_ip"] == "93.184.216.34"
    assert payload["findings"][0]["reasons"] == ["test reason"]
