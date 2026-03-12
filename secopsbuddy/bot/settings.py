from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(slots=True)
class BotSettings:
    token: str
    allowed_chat_ids: list[int]
    events_file: str
    bot_name: str

    @classmethod
    def from_env(cls, events_file: str, env_file: str = ".env") -> "BotSettings":
        load_dotenv(env_file, override=True)

        token = os.getenv("SECOPSBUDDY_BOT_TOKEN", "").strip()
        raw_ids = os.getenv("SECOPSBUDDY_BOT_ALLOWED_IDS", "").strip()
        bot_name = os.getenv("SECOPSBUDDY_BOT_NAME", "SecOps Buddy").strip() or "SecOps Buddy"
        events_override = os.getenv("SECOPSBUDDY_BOT_EVENTS_FILE", "").strip()

        if not token:
            raise ValueError("SECOPSBUDDY_BOT_TOKEN не задан в .env")

        allowed_chat_ids = _parse_chat_ids(raw_ids)
        if not allowed_chat_ids:
            raise ValueError("SECOPSBUDDY_BOT_ALLOWED_IDS не задан или пуст")

        resolved_events_file = events_override or events_file
        Path(resolved_events_file).parent.mkdir(parents=True, exist_ok=True)

        return cls(
            token=token,
            allowed_chat_ids=allowed_chat_ids,
            events_file=resolved_events_file,
            bot_name=bot_name,
        )

    def is_allowed(self, chat_id: int) -> bool:
        return chat_id in self.allowed_chat_ids


def _parse_chat_ids(raw_value: str) -> list[int]:
    if not raw_value:
        return []

    values = [item.strip() for item in raw_value.split(",") if item.strip()]
    parsed: list[int] = []
    for value in values:
        if not value.lstrip("-").isdigit():
            raise ValueError(f"Некорректный chat id: {value}")
        parsed.append(int(value))

    return parsed
