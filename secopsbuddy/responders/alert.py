from __future__ import annotations

import json

from secopsbuddy.models import DetectionResult
from secopsbuddy.responders.firewall import FirewallAction


class AlertResponder:
    @staticmethod
    def format_detection_result(result: DetectionResult, json_output: bool = False) -> str:
        if json_output:
            return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)

        lines = [
            "=== Результат детектирования SecOps Buddy ===",
            f"Детектор      : {result.detector_id} ({result.detector_name})",
            f"MITRE         : {result.mitre_id}",
            f"Статус        : {result.status}",
            f"Общий Score   : {result.score:.3f}",
            f"Время         : {result.timestamp}",
            f"Сводка        : {result.summary}",
        ]

        if not result.findings:
            lines.append("Находки       : нет")
            return "\n".join(lines)

        lines.append("")
        lines.append("Находки:")
        lines.append(
            "remote_ip        remote_port  proto  process         pid     hits  local_ports  score"
        )
        lines.append(
            "---------------  -----------  -----  --------------  ------  ----  -----------  -----"
        )

        for finding in result.findings:
            lines.append(
                f"{finding.remote_ip:<15}  "
                f"{str(finding.remote_port):<11}  "
                f"{finding.protocol:<5}  "
                f"{(finding.process_name or '-'): <14}  "
                f"{str(finding.pid or '-'): <6}  "
                f"{finding.hit_count:<4}  "
                f"{finding.distinct_local_ports:<11}  "
                f"{finding.score:.3f}"
            )
            for reason in finding.reasons:
                lines.append(f"  - {reason}")

        return "\n".join(lines)

    @staticmethod
    def format_firewall_actions(actions: list[FirewallAction]) -> str:
        if not actions:
            return "Firewall: действия не требуются."

        lines = ["", "Действия firewall:"]
        for action in actions:
            backend = f" [{action.backend}]" if action.backend else ""
            command = f" | cmd: {action.command}" if action.command else ""
            lines.append(f"- {action.ip}{backend}: {action.message}{command}")
        return "\n".join(lines)
