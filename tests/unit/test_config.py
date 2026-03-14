from __future__ import annotations

from pathlib import Path

import pytest

from secopsbuddy.config import (
    AppConfig,
    ConfigError,
    _parse_bool,
    _parse_port_list,
    load_config,
)


def test_parse_bool_supports_common_values() -> None:
    assert _parse_bool(True) is True
    assert _parse_bool(False) is False
    assert _parse_bool("true") is True
    assert _parse_bool("0") is False
    assert _parse_bool(1) is True
    assert _parse_bool(0) is False


@pytest.mark.parametrize("raw", ["maybe", object()])
def test_parse_bool_rejects_invalid_values(raw: object) -> None:
    with pytest.raises(ValueError):
        _parse_bool(raw)


def test_parse_port_list_deduplicates_and_validates() -> None:
    ports = _parse_port_list([443, "443", 53], field_name="allowed_remote_ports")

    assert ports == [443, 53]

    with pytest.raises(ValueError):
        _parse_port_list([70000], field_name="allowed_remote_ports")


def test_app_config_from_dict_normalizes_values() -> None:
    config = AppConfig.from_dict(
        {
            "dry_run": "false",
            "allowed_process_names": ["Python", " python ", "curl"],
            "allowed_remote_ports": [443, "443", 8443],
            "allowed_cidrs": ["10.0.0.0/24", "10.0.0.25/24"],
            "collector_command_preference": ["ss_tunp", "netstat_tunp"],
        }
    )

    assert config.dry_run is False
    assert config.allowed_process_names == ["python", "curl"]
    assert config.allowed_remote_ports == [443, 8443]
    assert config.allowed_cidrs == ["10.0.0.0/24"]
    assert config.collector_command_preference == ["ss_tunp", "netstat_tunp"]


def test_app_config_from_dict_rejects_invalid_thresholds() -> None:
    with pytest.raises(ConfigError):
        AppConfig.from_dict({"suspicion_threshold": 2})

    with pytest.raises(ConfigError):
        AppConfig.from_dict({"alert_cooldown_seconds": -1})


def test_load_config_reads_yaml_file(tmp_path: Path) -> None:
    config_file = tmp_path / "custom_config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "snapshot_count: 2",
                "snapshot_interval_seconds: 0",
                "suspicion_threshold: 0.5",
                "allowed_process_names: [\"SSH\"]",
                "alert_cooldown_seconds: 0",
            ]
        ),
        encoding="utf-8",
    )

    config = load_config(config_file)

    assert config.snapshot_count == 2
    assert config.snapshot_interval_seconds == 0.0
    assert config.suspicion_threshold == 0.5
    assert config.allowed_process_names == ["ssh"]
    assert config.alert_cooldown_seconds == 0


def test_load_config_raises_on_missing_file(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.yaml"

    with pytest.raises(ConfigError):
        load_config(missing_path)
