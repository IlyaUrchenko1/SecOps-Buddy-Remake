from __future__ import annotations

import hashlib
from html import escape
from typing import Any

from aiogram.types import InlineKeyboardMarkup

from secopsbuddy.bot.keyboards import alert_inline_keyboard


BOT_TITLE = "SecOps Buddy"


def render_event(
    event: dict[str, Any],
) -> tuple[str, InlineKeyboardMarkup | None, str] | None:
    event_type = str(event.get("event", ""))
    mitre_id = str(event.get("mitre_id", "")).upper()

    if event_type == "detector_started":
        detector_id = escape(str(event.get("detector_id", "unknown")))
        mode = escape(str(event.get("mode", "monitor")))
        continuous = bool(event.get("continuous", False))
        timestamp = escape(str(event.get("timestamp", "")))
        text = (
            f"<b>{BOT_TITLE}</b>\n"
            "Детектор запущен\n"
            f"Техника: <b>{escape(mitre_id or 'N/A')}</b>\n"
            f"Детектор: <code>{detector_id}</code>\n"
            f"Режим: <b>{mode}</b>\n"
            f"Формат: <b>{'continuous' if continuous else 'oneshot'}</b>\n"
            f"Время: <code>{timestamp}</code>"
        )
        keyboard = _build_keyboard(mitre_id, event)
        return text, keyboard, "lifecycle"

    if event_type == "detector_stopped":
        detector_id = escape(str(event.get("detector_id", "unknown")))
        mode = escape(str(event.get("mode", "monitor")))
        timestamp = escape(str(event.get("timestamp", "")))
        text = (
            f"<b>{BOT_TITLE}</b>\n"
            "Детектор остановлен\n"
            f"Техника: <b>{escape(mitre_id or 'N/A')}</b>\n"
            f"Детектор: <code>{detector_id}</code>\n"
            f"Режим: <b>{mode}</b>\n"
            f"Время: <code>{timestamp}</code>"
        )
        keyboard = _build_keyboard(mitre_id, event)
        return text, keyboard, "lifecycle"

    if event_type == "detection_result":
        status = str(event.get("status", "")).lower()
        if status == "clean":
            return None

        score = event.get("score", 0)
        findings_count = int(event.get("findings_count", 0) or 0)
        summary = escape(str(event.get("summary", "")))
        timestamp = escape(str(event.get("timestamp", "")))

        if status == "suspicious":
            lines = [
                f"<b>{BOT_TITLE}</b>",
                "Обнаружена подозрительная активность",
                f"MITRE: <b>{escape(mitre_id or 'N/A')}</b>",
                f"Score: <b>{score}</b>",
                f"Находок: <b>{findings_count}</b>",
                f"Сводка: {summary}",
                f"Время: <code>{timestamp}</code>",
            ]
            findings = event.get("findings") or []
            for finding in findings[:3]:
                remote_ip = escape(str(finding.get("remote_ip", "-")))
                remote_port = escape(str(finding.get("remote_port", "-")))
                proc = escape(str(finding.get("process_name", "-")))
                f_score = escape(str(finding.get("score", "-")))
                lines.append(
                    f"- <code>{remote_ip}:{remote_port}</code> | proc=<code>{proc}</code> | score=<b>{f_score}</b>"
                )
            text = "\n".join(lines)
            keyboard = _build_keyboard(mitre_id, event)
            return text, keyboard, "alert"

        text = (
            f"<b>{BOT_TITLE}</b>\n"
            "Ошибка в процессе детектирования\n"
            f"MITRE: <b>{escape(mitre_id or 'N/A')}</b>\n"
            f"Сводка: {summary}\n"
            f"Время: <code>{timestamp}</code>"
        )
        keyboard = _build_keyboard(mitre_id, event)
        return text, keyboard, "error"

    if event_type == "threat_mitigated":
        ip_value = escape(str(event.get("ip", "-")))
        timestamp = escape(str(event.get("timestamp", "")))
        text = (
            f"<b>{BOT_TITLE}</b>\n"
            "Угроза нейтрализована\n"
            f"MITRE: <b>{escape(mitre_id or 'N/A')}</b>\n"
            f"IP: <code>{ip_value}</code>\n"
            f"Время: <code>{timestamp}</code>"
        )
        keyboard = _build_keyboard(mitre_id, event)
        return text, keyboard, "mitigation"

    if event_type == "firewall_action":
        blocked = bool(event.get("blocked", False))
        if blocked:
            return None
        ip_value = escape(str(event.get("ip", "-")))
        message = escape(str(event.get("message", "")))
        text = (
            f"<b>{BOT_TITLE}</b>\n"
            "Действие firewall\n"
            f"MITRE: <b>{escape(mitre_id or 'N/A')}</b>\n"
            f"IP: <code>{ip_value}</code>\n"
            f"Сообщение: {message}"
        )
        keyboard = _build_keyboard(mitre_id, event)
        return text, keyboard, "action"

    return None


def _build_keyboard(mitre_id: str, event: dict[str, Any]) -> InlineKeyboardMarkup | None:
    if not mitre_id:
        return None
    seed = f"{event.get('event', '')}-{event.get('timestamp', '')}-{mitre_id}"
    ack_id = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
    return alert_inline_keyboard(
        mitre_id=mitre_id,
        ack_id=ack_id,
        mitre_url=f"https://attack.mitre.org/techniques/{mitre_id}/",
    )
