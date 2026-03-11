from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from ipaddress import ip_address
from typing import Sequence

from secopsbuddy.models import ConnectionRecord
from secopsbuddy.utils.time_utils import utc_now_iso


class CollectorError(RuntimeError):
    pass


class NetworkSnapshotCollector:
    COMMANDS: dict[str, list[str]] = {
        "ss_tunp": ["ss", "-H", "-tunp"],
        "ss_tun": ["ss", "-H", "-tun"],
        "ss_tpn": ["ss", "-H", "-tpn"],
        "netstat_tunp": ["netstat", "-tunp"],
    }

    _SS_LINE_RE = re.compile(
        r"^(?P<proto>\S+)\s+(?P<state>\S+)\s+\S+\s+\S+\s+(?P<local>\S+)\s+(?P<remote>\S+)(?:\s+(?P<process>.+))?$"
    )

    def __init__(
        self,
        command_preference: Sequence[str] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.command_preference = list(command_preference or self.COMMANDS.keys())
        self.logger = logger or logging.getLogger("secopsbuddy.collector")

    def collect_series(
        self,
        snapshot_count: int,
        snapshot_interval_seconds: float,
    ) -> list[list[ConnectionRecord]]:
        snapshots: list[list[ConnectionRecord]] = []
        for index in range(snapshot_count):
            snapshots.append(self.collect_snapshot())
            if index < snapshot_count - 1 and snapshot_interval_seconds > 0:
                time.sleep(snapshot_interval_seconds)
        return snapshots

    def collect_snapshot(self) -> list[ConnectionRecord]:
        errors: list[str] = []

        for command_key in self.command_preference:
            command = self.COMMANDS.get(command_key)
            if not command:
                continue
            if shutil.which(command[0]) is None:
                errors.append(f"{command[0]} не найден")
                continue

            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                timestamp = utc_now_iso()
                if command[0] == "ss":
                    return self._parse_ss_output(result.stdout, timestamp)
                return self._parse_netstat_output(result.stdout, timestamp)
            except subprocess.CalledProcessError as exc:
                stderr = (exc.stderr or "").strip()
                errors.append(f"{' '.join(command)} завершилась ошибкой: {stderr or exc.returncode}")
                self.logger.warning("Команда коллектора завершилась с ошибкой: %s", errors[-1])
            except OSError as exc:
                errors.append(f"{' '.join(command)} не выполнена: {exc}")
                self.logger.warning("Команда коллектора завершилась с ошибкой: %s", errors[-1])

        raise CollectorError("Не удалось выполнить ни одну команду коллектора. " + "; ".join(errors))

    def _parse_ss_output(self, output: str, timestamp: str) -> list[ConnectionRecord]:
        records: list[ConnectionRecord] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line or line.lower().startswith("netid"):
                continue
            parsed = self._parse_ss_line(line, timestamp)
            if parsed:
                records.append(parsed)
        return records

    def _parse_ss_line(self, line: str, timestamp: str) -> ConnectionRecord | None:
        match = self._SS_LINE_RE.match(line)
        if not match:
            return None

        local_ip, local_port = self._parse_address_port(match.group("local"))
        remote_ip, remote_port = self._parse_address_port(match.group("remote"))
        process_name, pid = self._parse_ss_process(match.group("process"))

        return ConnectionRecord(
            timestamp=timestamp,
            proto=match.group("proto"),
            state=match.group("state"),
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            pid=pid,
            process_name=process_name,
        )

    def _parse_netstat_output(self, output: str, timestamp: str) -> list[ConnectionRecord]:
        records: list[ConnectionRecord] = []
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lowered = line.lower()
            if lowered.startswith("proto") or lowered.startswith("active"):
                continue

            parsed = self._parse_netstat_line(line, timestamp)
            if parsed:
                records.append(parsed)

        return records

    def _parse_netstat_line(self, line: str, timestamp: str) -> ConnectionRecord | None:
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            return None

        proto = parts[0]
        local_raw = parts[3]
        remote_raw = parts[4]

        state = "UNKNOWN"
        pid_program: str | None = None

        if len(parts) >= 7:
            state = parts[5]
            pid_program = parts[6]
        elif len(parts) == 6:
            if "/" in parts[5] or parts[5] == "-":
                pid_program = parts[5]
            else:
                state = parts[5]

        process_name, pid = self._parse_netstat_pid_program(pid_program)
        local_ip, local_port = self._parse_address_port(local_raw)
        remote_ip, remote_port = self._parse_address_port(remote_raw)

        return ConnectionRecord(
            timestamp=timestamp,
            proto=proto,
            state=state,
            local_ip=local_ip,
            local_port=local_port,
            remote_ip=remote_ip,
            remote_port=remote_port,
            pid=pid,
            process_name=process_name,
        )

    @staticmethod
    def _parse_ss_process(raw: str | None) -> tuple[str | None, int | None]:
        if not raw:
            return None, None

        pid_match = re.search(r"pid=(\d+)", raw)
        pid = int(pid_match.group(1)) if pid_match else None

        name_match = re.search(r'"([^"]+)"', raw)
        name = name_match.group(1) if name_match else None

        return name, pid

    @staticmethod
    def _parse_netstat_pid_program(raw: str | None) -> tuple[str | None, int | None]:
        if not raw or raw == "-":
            return None, None

        if "/" not in raw:
            if raw.isdigit():
                return None, int(raw)
            return raw, None

        pid_raw, process_name = raw.split("/", 1)
        pid = int(pid_raw) if pid_raw.isdigit() else None
        process = process_name or None
        return process, pid

    @staticmethod
    def _parse_address_port(raw: str) -> tuple[str | None, int | None]:
        value = raw.strip()
        if not value or value in {"*", "-"}:
            return None, None

        ip_part: str
        port_part: str

        if value.startswith("[") and "]" in value:
            ip_part, remainder = value[1:].split("]", 1)
            port_part = remainder[1:] if remainder.startswith(":") else ""
        else:
            ip_part, separator, port_part = value.rpartition(":")
            if not separator:
                ip_part, port_part = value, ""

        if "%" in ip_part:
            ip_part = ip_part.split("%", 1)[0]

        ip_part = ip_part.strip() or None
        port_part = port_part.strip()

        port: int | None = int(port_part) if port_part.isdigit() else None

        return ip_part, port


def is_routable_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_obj = ip_address(value)
    except ValueError:
        return False
    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified:
        return False
    return True
