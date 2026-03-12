from __future__ import annotations

from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)


def main_reply_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        resize_keyboard=True,
        keyboard=[
            [
                KeyboardButton(text="Статус"),
                KeyboardButton(text="Последние алерты"),
            ],
            [
                KeyboardButton(text="Mute/Unmute"),
                KeyboardButton(text="Помощь"),
            ],
        ],
    )


def alert_inline_keyboard(mitre_id: str, ack_id: str, mitre_url: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="ACK ✅", callback_data=f"ack:{ack_id}"),
                InlineKeyboardButton(text="MITRE", url=mitre_url),
            ]
        ]
    )


def status_inline_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Обновить статус", callback_data="refresh_status"),
            ]
        ]
    )
