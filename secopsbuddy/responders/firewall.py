from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable


@dataclass(slots=True)
class FirewallAction:
    ip: str
    blocked: bool
    message: str
    backend: str | None = None
    command: str | None = None


class FirewallResponder:
    def __init__(
        self,
        dry_run: bool,
        block_private_ips: bool,
        logger: logging.Logger | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.block_private_ips = block_private_ips
        self.logger = logger or logging.getLogger("secopsbuddy.firewall")

    def is_blockable_ip(self, ip_raw: str) -> tuple[bool, str]:
        value = (ip_raw or "").strip()
        if not value:
            return False, "пустой IP"

        try:
            ip_obj = ipaddress.ip_address(value)
        except ValueError:
            return False, "некорректный IP"

        if ip_obj.is_loopback:
            return False, "loopback IP нельзя блокировать"

        if not self.block_private_ips and (
            ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_reserved
        ):
            return False, "приватный/локальный/зарезервированный IP запрещен политикой"

        return True, "ok"

    def block_ips(self, ips: Iterable[str]) -> list[FirewallAction]:
        unique_ips = self._dedupe_preserve_order(ips)
        actions: list[FirewallAction] = []

        blockable_targets: list[str] = []
        for ip_raw in unique_ips:
            is_valid, reason = self.is_blockable_ip(ip_raw)
            if not is_valid:
                message = f"Пропуск {ip_raw}: {reason}"
                self.logger.warning(message)
                actions.append(FirewallAction(ip=ip_raw, blocked=False, message=message))
                continue
            blockable_targets.append(ip_raw)

        if not blockable_targets:
            return actions

        backend = self._detect_backend()
        if backend is None:
            message = "Не найден поддерживаемый backend firewall (ufw/iptables)."
            self.logger.error(message)
            for ip_raw in blockable_targets:
                actions.append(FirewallAction(ip=ip_raw, blocked=False, message=message))
            return actions

        for ip_raw in blockable_targets:
            command = self._build_block_command(backend, ip_raw)
            command_str = " ".join(command)

            if self.dry_run:
                msg = f"Dry-run: была бы выполнена команда `{command_str}`"
                self.logger.info(msg)
                actions.append(
                    FirewallAction(
                        ip=ip_raw,
                        blocked=False,
                        message=msg,
                        backend=backend,
                        command=command_str,
                    )
                )
                continue

            try:
                self._run_command(command)
                msg = f"Удаленный IP {ip_raw} заблокирован через {backend}."
                self.logger.warning(msg)
                actions.append(
                    FirewallAction(
                        ip=ip_raw,
                        blocked=True,
                        message=msg,
                        backend=backend,
                        command=command_str,
                    )
                )
            except PermissionError:
                msg = f"Недостаточно прав для применения правила firewall к {ip_raw}."
                self.logger.error(msg)
                actions.append(
                    FirewallAction(
                        ip=ip_raw,
                        blocked=False,
                        message=msg,
                        backend=backend,
                        command=command_str,
                    )
                )
            except subprocess.CalledProcessError as exc:
                stderr = (exc.stderr or "").strip()
                msg = f"Команда firewall завершилась ошибкой для {ip_raw}: {stderr or exc.returncode}"
                self.logger.error(msg)
                actions.append(
                    FirewallAction(
                        ip=ip_raw,
                        blocked=False,
                        message=msg,
                        backend=backend,
                        command=command_str,
                    )
                )
            except OSError as exc:
                msg = f"Не удалось выполнить firewall-команду для {ip_raw}: {exc}"
                self.logger.error(msg)
                actions.append(
                    FirewallAction(
                        ip=ip_raw,
                        blocked=False,
                        message=msg,
                        backend=backend,
                        command=command_str,
                    )
                )

        return actions

    @staticmethod
    def _dedupe_preserve_order(values: Iterable[str]) -> list[str]:
        seen: set[str] = set()
        output: list[str] = []
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            output.append(value)
        return output

    @staticmethod
    def _detect_backend() -> str | None:
        if shutil.which("ufw"):
            return "ufw"
        if shutil.which("iptables"):
            return "iptables"
        return None

    @staticmethod
    def _build_block_command(backend: str, ip_raw: str) -> list[str]:
        if backend == "ufw":
            return ["ufw", "deny", "out", "to", ip_raw]
        return ["iptables", "-A", "OUTPUT", "-d", ip_raw, "-j", "DROP"]

    @staticmethod
    def _run_command(command: list[str]) -> None:
        subprocess.run(command, check=True, capture_output=True, text=True)
