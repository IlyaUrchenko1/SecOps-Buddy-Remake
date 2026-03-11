from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field

from secopsbuddy.collectors.network_snapshot import CollectorError, NetworkSnapshotCollector
from secopsbuddy.config import AppConfig
from secopsbuddy.detectors.base import BaseDetector
from secopsbuddy.models import ConnectionRecord, DetectionFinding, DetectionResult
from secopsbuddy.utils.time_utils import utc_now_iso


@dataclass(slots=True)
class _GroupMetrics:
    remote_ip: str
    remote_port: int | None
    protocol: str
    process_name: str | None
    pid: int | None
    hit_count: int = 0
    local_ports: set[int] = field(default_factory=set)
    snapshot_ids: set[int] = field(default_factory=set)


class T1030Detector(BaseDetector):
    detector_id = "t1030"
    mitre_id = "T1030"
    name = "Эвристический детектор Data Transfer Size Limits"
    description = (
        "Ищет повторяющиеся исходящие соединения, похожие на дробную эксфильтрацию "
        "данных (поведенческий proxy для ATT&CK T1030)."
    )

    SAFE_PORTS = {53, 67, 68, 123}

    def __init__(
        self,
        config: AppConfig,
        collector: NetworkSnapshotCollector | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("secopsbuddy.detector.t1030")
        self.collector = collector or NetworkSnapshotCollector(
            command_preference=config.collector_command_preference,
            logger=self.logger,
        )

    def run(self) -> DetectionResult:
        timestamp = utc_now_iso()
        self.logger.info(
            "Запуск детектора=%s mitre=%s snapshots=%s interval=%s",
            self.detector_id,
            self.mitre_id,
            self.config.snapshot_count,
            self.config.snapshot_interval_seconds,
        )

        try:
            snapshots = self.collector.collect_series(
                snapshot_count=self.config.snapshot_count,
                snapshot_interval_seconds=self.config.snapshot_interval_seconds,
            )
        except CollectorError as exc:
            self.logger.error("Ошибка коллектора: %s", exc)
            return DetectionResult(
                detector_id=self.detector_id,
                mitre_id=self.mitre_id,
                detector_name=self.name,
                status="error",
                score=0.0,
                findings=[],
                summary=f"Коллектор не отработал: {exc}",
                timestamp=timestamp,
            )

        if not snapshots:
            return DetectionResult(
                detector_id=self.detector_id,
                mitre_id=self.mitre_id,
                detector_name=self.name,
                status="clean",
                score=0.0,
                findings=[],
                summary="Снимки не были собраны.",
                timestamp=timestamp,
            )

        grouped = self._group_connections(snapshots)
        if not grouped:
            return DetectionResult(
                detector_id=self.detector_id,
                mitre_id=self.mitre_id,
                detector_name=self.name,
                status="clean",
                score=0.0,
                findings=[],
                summary="Подходящих исходящих соединений в снимках не обнаружено.",
                timestamp=timestamp,
            )

        findings: list[DetectionFinding] = []
        scores: list[float] = []

        for metrics in grouped.values():
            score, reasons = self._score_group(metrics, total_snapshots=len(snapshots))
            scores.append(score)

            is_suspicious = (
                score >= self.config.suspicion_threshold
                and metrics.hit_count >= self.config.min_hits
                and len(metrics.local_ports) >= self.config.min_distinct_local_ports
            )
            if not is_suspicious:
                continue

            findings.append(
                DetectionFinding(
                    remote_ip=metrics.remote_ip,
                    remote_port=metrics.remote_port,
                    protocol=metrics.protocol,
                    pid=metrics.pid,
                    process_name=metrics.process_name,
                    hit_count=metrics.hit_count,
                    distinct_local_ports=len(metrics.local_ports),
                    score=round(score, 3),
                    reasons=reasons,
                )
            )

        findings.sort(key=lambda item: item.score, reverse=True)
        overall_score = max(scores) if scores else 0.0

        if findings:
            status = "suspicious"
            summary = (
                f"Обнаружены подозрительные повторяющиеся исходящие паттерны: {len(findings)}. "
                f"Макс. score={overall_score:.3f}."
            )
        else:
            status = "clean"
            summary = (
                f"Подозрительных T1030 proxy-паттернов не найдено. "
                f"Макс. наблюдаемый score={overall_score:.3f}."
            )

        return DetectionResult(
            detector_id=self.detector_id,
            mitre_id=self.mitre_id,
            detector_name=self.name,
            status=status,
            score=round(overall_score, 3),
            findings=findings,
            summary=summary,
            timestamp=timestamp,
        )

    def _group_connections(
        self,
        snapshots: list[list[ConnectionRecord]],
    ) -> dict[tuple[str, int | None, str, str | None], _GroupMetrics]:
        grouped: dict[tuple[str, int | None, str, str | None], _GroupMetrics] = {}

        for snapshot_index, snapshot in enumerate(snapshots):
            for conn in snapshot:
                if not self._is_outbound_candidate(conn):
                    continue

                remote_ip = conn.remote_ip or "unknown"
                key = (remote_ip, conn.remote_port, conn.proto.lower(), conn.process_name)

                if key not in grouped:
                    grouped[key] = _GroupMetrics(
                        remote_ip=remote_ip,
                        remote_port=conn.remote_port,
                        protocol=conn.proto.lower(),
                        process_name=conn.process_name,
                        pid=conn.pid,
                    )

                item = grouped[key]
                item.hit_count += 1
                if conn.local_port is not None:
                    item.local_ports.add(conn.local_port)
                item.snapshot_ids.add(snapshot_index)
                if item.pid is None and conn.pid is not None:
                    item.pid = conn.pid

        return grouped

    def _is_outbound_candidate(self, conn: ConnectionRecord) -> bool:
        if not conn.remote_ip or conn.remote_port is None:
            return False
        if conn.state.upper() == "LISTEN":
            return False
        if conn.remote_ip in {"0.0.0.0", "::", "*"}:
            return False
        return True

    def _score_group(self, metrics: _GroupMetrics, total_snapshots: int) -> tuple[float, list[str]]:
        reasons: list[str] = []

        hit_ratio = min(metrics.hit_count / max(self.config.min_hits * 2, 1), 1.0)
        local_port_ratio = min(
            len(metrics.local_ports) / max(self.config.min_distinct_local_ports * 2, 1),
            1.0,
        )
        snapshot_ratio = len(metrics.snapshot_ids) / max(total_snapshots, 1)

        score = 0.4 * hit_ratio + 0.25 * local_port_ratio + 0.25 * snapshot_ratio

        if metrics.hit_count >= self.config.min_hits:
            reasons.append(
                f"Высокая повторяемость: {metrics.hit_count} появлений (минимум {self.config.min_hits})."
            )
            score += 0.05

        if len(metrics.local_ports) >= self.config.min_distinct_local_ports:
            reasons.append(
                "Много разных локальных ephemeral-портов, что похоже на серию коротких сессий."
            )
            score += 0.05

        if snapshot_ratio >= 0.6:
            reasons.append(
                f"Паттерн присутствует во многих снимках (доля {snapshot_ratio:.2f})."
            )
            score += 0.05

        if metrics.process_name:
            reasons.append("Есть привязка к процессу, это повышает уверенность.")
            score += 0.03

        if metrics.remote_port in self.SAFE_PORTS:
            reasons.append(
                f"Порт {metrics.remote_port} типичен для инфраструктурных сервисов, score снижен."
            )
            score -= 0.1

        if self._is_non_routable(metrics.remote_ip):
            reasons.append("Назначение приватное/локальное/зарезервированное, score снижен.")
            score -= 0.25

        score = max(0.0, min(score, 1.0))
        return score, reasons

    @staticmethod
    def _is_non_routable(ip_raw: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_raw)
        except ValueError:
            return False
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
        )
