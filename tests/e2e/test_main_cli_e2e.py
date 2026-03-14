from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from secopsbuddy import main as app_main
from secopsbuddy.config import AppConfig
from secopsbuddy.registry import DetectorRegistry


class FakeDetector:
    detector_id = "fake"
    mitre_id = "T0000"
    name = "Fake Detector"
    description = "Fake detector for CLI e2e"

    def run(self):
        raise AssertionError("run() should not be called for --list")


class FakeLogger:
    def info(self, *_args, **_kwargs) -> None:
        return None


def test_e2e_main_list_command_outputs_registry(monkeypatch, capsys) -> None:
    registry = DetectorRegistry()
    registry.register(FakeDetector())

    monkeypatch.setattr(app_main, "_load_config_safely", lambda _path: AppConfig())
    monkeypatch.setattr(app_main, "setup_logging", lambda **_kwargs: FakeLogger())
    monkeypatch.setattr(app_main, "create_default_registry", lambda config, logger: registry)

    code = app_main.main(["--list"])
    output = capsys.readouterr().out

    assert code == 0
    assert "Доступные детекторы" in output
    assert "fake" in output


def test_e2e_main_run_pipeline_with_mocked_collector(monkeypatch, tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "\n".join(
            [
                "snapshot_count: 6",
                "snapshot_interval_seconds: 0",
                "suspicion_threshold: 0.8",
                "min_hits: 4",
                "min_distinct_local_ports: 3",
                "collector_command_preference: [ss_tunp]",
                f"log_file: {tmp_path / 'logs' / 'app.log'}",
                f"log_error_file: {tmp_path / 'logs' / 'errors.log'}",
                f"log_results_file: {tmp_path / 'logs' / 'results.log'}",
                f"log_actions_file: {tmp_path / 'logs' / 'actions.log'}",
                f"log_events_file: {tmp_path / 'logs' / 'events.log'}",
                f"mitre_log_dir: {tmp_path / 'logs' / 'mitre'}",
                f"bot_events_file: {tmp_path / 'runtime' / 'bot_events.jsonl'}",
                f"bot_pid_file: {tmp_path / 'runtime' / 'bot.pid'}",
                f"bot_log_file: {tmp_path / 'logs' / 'bot.log'}",
                f"bot_error_log_file: {tmp_path / 'logs' / 'bot_errors.log'}",
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.shutil.which", lambda _name: "/usr/bin/ss")

    state = {"port": 45000}

    def _fake_run(command: list[str], capture_output: bool, text: bool, check: bool):
        port = state["port"]
        state["port"] += 1
        line = (
            f"tcp ESTAB 0 0 10.0.0.10:{port} 93.184.216.34:443 "
            "users:((\"python\",pid=4321,fd=5))\n"
        )
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=line,
            stderr="",
        )

    monkeypatch.setattr("secopsbuddy.collectors.network_snapshot.subprocess.run", _fake_run)

    code = app_main.main(["--run", "t1030", "--json", "--config", str(config_path)])
    output = capsys.readouterr().out

    assert code == 0
    assert '"detector_id": "t1030"' in output
    assert '"status": "suspicious"' in output


def test_e2e_main_returns_error_for_missing_config(capsys, tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"

    code = app_main.main(["--list", "--config", str(missing_path)])
    output = capsys.readouterr().out

    assert code == 2
    assert "Не удалось загрузить конфиг" in output
