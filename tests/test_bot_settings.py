from pathlib import Path

import pytest

from secopsbuddy.bot.settings import BotSettings


def test_bot_settings_from_env_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SECOPSBUDDY_BOT_TOKEN=test-token",
                "SECOPSBUDDY_BOT_ALLOWED_IDS=123,456",
                "SECOPSBUDDY_BOT_NAME=Test Bot",
            ]
        ),
        encoding="utf-8",
    )

    settings = BotSettings.from_env(
        events_file=str(tmp_path / "events.jsonl"),
        env_file=str(env_file),
    )

    assert settings.token == "test-token"
    assert settings.allowed_chat_ids == [123, 456]
    assert settings.bot_name == "Test Bot"


def test_bot_settings_reads_bom_prefixed_token_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "\ufeffSECOPSBUDDY_BOT_TOKEN=test-token",
                "SECOPSBUDDY_BOT_ALLOWED_IDS=123",
            ]
        ),
        encoding="utf-8",
    )

    settings = BotSettings.from_env(
        events_file=str(tmp_path / "events.jsonl"),
        env_file=str(env_file),
    )

    assert settings.token == "test-token"
    assert settings.allowed_chat_ids == [123]


def test_bot_settings_invalid_chat_id_raises(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "SECOPSBUDDY_BOT_TOKEN=test-token",
                "SECOPSBUDDY_BOT_ALLOWED_IDS=abc",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        BotSettings.from_env(
            events_file=str(tmp_path / "events.jsonl"),
            env_file=str(env_file),
        )
