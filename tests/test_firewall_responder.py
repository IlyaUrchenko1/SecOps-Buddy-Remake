from __future__ import annotations

import subprocess

from secopsbuddy.responders.firewall import FirewallResponder


def test_is_blockable_ip_rejects_private_loopback_and_invalid() -> None:
    responder = FirewallResponder(dry_run=True, block_private_ips=False)

    assert responder.is_blockable_ip("8.8.8.8") == (True, "ok")
    assert responder.is_blockable_ip("192.168.1.10")[0] is False
    assert responder.is_blockable_ip("127.0.0.1")[0] is False
    assert responder.is_blockable_ip("not-an-ip")[0] is False


def test_is_blockable_ip_allows_private_if_policy_enabled() -> None:
    responder = FirewallResponder(dry_run=True, block_private_ips=True)

    assert responder.is_blockable_ip("192.168.1.10") == (True, "ok")
    assert responder.is_blockable_ip("10.0.0.7") == (True, "ok")


def test_block_ips_dedupes_and_skips_non_blockable_without_system_commands(monkeypatch) -> None:
    responder = FirewallResponder(dry_run=True, block_private_ips=False)

    monkeypatch.setattr(FirewallResponder, "_detect_backend", staticmethod(lambda: "ufw"))

    def _should_not_run(_command: list[str]) -> None:
        raise AssertionError("_run_command must not be called in dry-run mode")

    monkeypatch.setattr(FirewallResponder, "_run_command", staticmethod(_should_not_run))

    actions = responder.block_ips(["8.8.8.8", "8.8.8.8", "127.0.0.1"])

    assert [action.ip for action in actions] == ["127.0.0.1", "8.8.8.8"]
    assert actions[0].blocked is False
    assert "Пропуск" in actions[0].message
    assert actions[1].blocked is False
    assert actions[1].backend == "ufw"
    assert actions[1].command == "ufw deny out to 8.8.8.8"


def test_block_ips_returns_error_when_backend_missing(monkeypatch) -> None:
    responder = FirewallResponder(dry_run=False, block_private_ips=True)

    monkeypatch.setattr(FirewallResponder, "_detect_backend", staticmethod(lambda: None))

    actions = responder.block_ips(["1.1.1.1"])

    assert len(actions) == 1
    assert actions[0].blocked is False
    assert "Не найден поддерживаемый backend firewall" in actions[0].message


def test_block_ips_handles_firewall_command_failure(monkeypatch) -> None:
    responder = FirewallResponder(dry_run=False, block_private_ips=True)

    monkeypatch.setattr(FirewallResponder, "_detect_backend", staticmethod(lambda: "iptables"))

    def _raise_called_process_error(_command: list[str]) -> None:
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["iptables"],
            stderr="permission denied",
        )

    monkeypatch.setattr(
        FirewallResponder,
        "_run_command",
        staticmethod(_raise_called_process_error),
    )

    actions = responder.block_ips(["8.8.4.4"])

    assert len(actions) == 1
    assert actions[0].blocked is False
    assert actions[0].backend == "iptables"
    assert actions[0].command == "iptables -A OUTPUT -d 8.8.4.4 -j DROP"
    assert "ошибкой" in actions[0].message
