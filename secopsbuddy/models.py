from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal


DetectionStatus = Literal["clean", "suspicious", "error"]


@dataclass(slots=True)
class ConnectionRecord:
    timestamp: str
    proto: str
    state: str
    local_ip: str | None
    local_port: int | None
    remote_ip: str | None
    remote_port: int | None
    pid: int | None
    process_name: str | None


@dataclass(slots=True)
class DetectionFinding:
    remote_ip: str
    remote_port: int | None
    protocol: str
    pid: int | None
    process_name: str | None
    hit_count: int
    distinct_local_ports: int
    score: float
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DetectionResult:
    detector_id: str
    mitre_id: str
    detector_name: str
    status: DetectionStatus
    score: float
    findings: list[DetectionFinding]
    summary: str
    timestamp: str

    def to_dict(self) -> dict:
        return asdict(self)
