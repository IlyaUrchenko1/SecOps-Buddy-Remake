from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

from secopsbuddy.bot.settings import BotSettings
from secopsbuddy.bot.state import BotRuntimeState
from secopsbuddy.bot.worker import _stream_events


class FakeBot:
    def __init__(self) -> None:
        self.messages: list[tuple[int, str]] = []

    async def send_message(
        self,
        chat_id: int,
        text: str,
        disable_web_page_preview: bool = True,
        reply_markup: object | None = None,
    ) -> None:
        self.messages.append((chat_id, text))


async def _run_stream_scenario(events_file: Path) -> tuple[list[tuple[int, str]], str]:
    settings = BotSettings(
        token="token",
        allowed_chat_ids=[1001],
        events_file=str(events_file),
        bot_name="SecOps Buddy",
    )
    state = BotRuntimeState()
    stop_event = asyncio.Event()
    logger = logging.getLogger("secopsbuddy.test.e2e.stream")
    bot = FakeBot()

    task = asyncio.create_task(
        _stream_events(
            bot=bot,
            settings=settings,
            state=state,
            stop_event=stop_event,
            logger=logger,
        )
    )

    await asyncio.sleep(0.1)

    event = {
        "event": "detection_result",
        "mitre_id": "T1030",
        "status": "suspicious",
        "score": 0.95,
        "findings_count": 1,
        "summary": "pipeline event",
        "timestamp": "2026-03-14T00:00:00Z",
        "findings": [
            {
                "remote_ip": "93.184.216.34",
                "remote_port": 443,
                "process_name": "python",
                "score": 0.95,
            }
        ],
    }

    with events_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

    await asyncio.sleep(1.2)
    stop_event.set()
    await asyncio.wait_for(task, timeout=2.0)

    return bot.messages, state.recent_alerts_text()


def test_p2p_worker_stream_reads_event_file_and_broadcasts_alert(tmp_path: Path) -> None:
    events_file = tmp_path / "events.jsonl"
    events_file.write_text("", encoding="utf-8")

    messages, recent_alerts = asyncio.run(_run_stream_scenario(events_file))

    assert len(messages) == 1
    assert messages[0][0] == 1001
    assert "подозрительная активность" in messages[0][1].lower()
    assert "pipeline event" in recent_alerts
