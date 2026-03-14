from __future__ import annotations

import json

from secopsbuddy.models import DetectionFinding, DetectionResult
from secopsbuddy.responders.alert import AlertResponder
from secopsbuddy.responders.firewall import FirewallAction


def _sample_result() -> DetectionResult:
    return DetectionResult(
        detector_id="t1030",
        mitre_id="T1030",
        detector_name="Detector Name",
        status="suspicious",
        score=0.95,
        findings=[
            DetectionFinding(
                remote_ip="93.184.216.34",
                remote_port=443,
                protocol="tcp",
                pid=1234,
                process_name="python",
                hit_count=8,
                distinct_local_ports=6,
                score=0.95,
                reasons=["reason one", "reason two"],
            )
        ],
        summary="summary text",
        timestamp="2026-03-14T00:00:00Z",
    )


def test_format_detection_result_as_json() -> None:
    payload = AlertResponder.format_detection_result(_sample_result(), json_output=True)
    data = json.loads(payload)

    assert data["detector_id"] == "t1030"
    assert data["findings"][0]["remote_ip"] == "93.184.216.34"


def test_format_detection_result_as_human_readable_text() -> None:
    output = AlertResponder.format_detection_result(_sample_result(), json_output=False)

    assert "Результат детектирования" in output
    assert "t1030" in output
    assert "93.184.216.34" in output
    assert "reason one" in output


def test_format_detection_result_without_findings() -> None:
    result = _sample_result()
    result.findings = []
    result.status = "clean"

    output = AlertResponder.format_detection_result(result, json_output=False)

    assert "Находки       : нет" in output


def test_format_firewall_actions_empty_and_non_empty() -> None:
    assert AlertResponder.format_firewall_actions([]) == "Firewall: действия не требуются."

    output = AlertResponder.format_firewall_actions(
        [
            FirewallAction(
                ip="8.8.8.8",
                blocked=True,
                message="blocked",
                backend="ufw",
                command="ufw deny out to 8.8.8.8",
            )
        ]
    )

    assert "Действия firewall:" in output
    assert "8.8.8.8" in output
    assert "ufw" in output
