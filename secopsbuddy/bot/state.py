from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from secopsbuddy.utils.time_utils import utc_now_iso


@dataclass(slots=True)
class BotRuntimeState:
    started_at: str = field(default_factory=utc_now_iso)
    recent_alerts: deque[str] = field(default_factory=lambda: deque(maxlen=30))
    muted_chat_ids: set[int] = field(default_factory=set)

    def add_alert(self, text: str) -> None:
        self.recent_alerts.appendleft(text)

    def recent_alerts_text(self) -> str:
        if not self.recent_alerts:
            return "Пока нет зафиксированных алертов."
        output: list[str] = []
        for index, item in enumerate(self.recent_alerts, start=1):
            output.append(f"{index}. {item}")
        return "\n".join(output)

    def toggle_mute(self, chat_id: int) -> bool:
        if chat_id in self.muted_chat_ids:
            self.muted_chat_ids.remove(chat_id)
            return False
        self.muted_chat_ids.add(chat_id)
        return True

    def is_muted(self, chat_id: int) -> bool:
        return chat_id in self.muted_chat_ids
