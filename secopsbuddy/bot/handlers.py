from __future__ import annotations

from aiogram import F, Router
from aiogram.filters import Command, CommandStart
from aiogram.types import CallbackQuery, Message

from secopsbuddy.bot.keyboards import main_reply_keyboard, status_inline_keyboard
from secopsbuddy.bot.settings import BotSettings
from secopsbuddy.bot.state import BotRuntimeState


def build_router(state: BotRuntimeState, settings: BotSettings) -> Router:
    router = Router(name="secopsbuddy_bot_router")

    @router.message(CommandStart())
    async def cmd_start(message: Message) -> None:
        if not _is_allowed(message.chat.id, settings):
            await message.answer("Доступ ограничен.")
            return
        await message.answer(
            (
                "SecOps Buddy Bot онлайн.\n"
                "Используйте кнопки ниже или команды /status, /help, /mute"
            ),
            reply_markup=main_reply_keyboard(),
        )

    @router.message(Command("help"))
    async def cmd_help(message: Message) -> None:
        if not _is_allowed(message.chat.id, settings):
            await message.answer("Доступ ограничен.")
            return
        await message.answer(
            "Команды:\n"
            "/status — текущее состояние\n"
            "/mute — включить/выключить временный mute алертов\n"
            "/help — подсказка\n"
            "Кнопки: Статус, Последние алерты, Mute/Unmute, Помощь",
            reply_markup=main_reply_keyboard(),
        )

    @router.message(Command("status"))
    async def cmd_status(message: Message) -> None:
        if not _is_allowed(message.chat.id, settings):
            await message.answer("Доступ ограничен.")
            return
        await message.answer(
            _status_text(message.chat.id, state),
            reply_markup=status_inline_keyboard(),
        )

    @router.message(Command("mute"))
    async def cmd_mute(message: Message) -> None:
        if not _is_allowed(message.chat.id, settings):
            await message.answer("Доступ ограничен.")
            return
        muted = state.toggle_mute(message.chat.id)
        await message.answer(
            "Уведомления по алертам выключены." if muted else "Уведомления по алертам включены."
        )

    @router.message(F.text == "Статус")
    async def btn_status(message: Message) -> None:
        await cmd_status(message)

    @router.message(F.text == "Последние алерты")
    async def btn_last_alerts(message: Message) -> None:
        if not _is_allowed(message.chat.id, settings):
            await message.answer("Доступ ограничен.")
            return
        await message.answer(state.recent_alerts_text())

    @router.message(F.text == "Mute/Unmute")
    async def btn_mute(message: Message) -> None:
        await cmd_mute(message)

    @router.message(F.text == "Помощь")
    async def btn_help(message: Message) -> None:
        await cmd_help(message)

    @router.callback_query(F.data == "refresh_status")
    async def cb_refresh_status(callback: CallbackQuery) -> None:
        if callback.message is None:
            await callback.answer("Нет данных")
            return
        if not _is_allowed(callback.message.chat.id, settings):
            await callback.answer("Доступ ограничен", show_alert=True)
            return
        await callback.message.answer(_status_text(callback.message.chat.id, state))
        await callback.answer("Статус обновлен")

    @router.callback_query(F.data.startswith("ack:"))
    async def cb_ack(callback: CallbackQuery) -> None:
        if callback.message is None:
            await callback.answer("Нет данных")
            return
        if not _is_allowed(callback.message.chat.id, settings):
            await callback.answer("Доступ ограничен", show_alert=True)
            return
        await callback.answer("Принято")

    return router


def _is_allowed(chat_id: int, settings: BotSettings) -> bool:
    return settings.is_allowed(chat_id)


def _status_text(chat_id: int, state: BotRuntimeState) -> str:
    return (
        "Статус бота:\n"
        f"Запущен: {state.started_at}\n"
        f"Mute для этого чата: {'включен' if state.is_muted(chat_id) else 'выключен'}\n"
        f"Кэш алертов: {len(state.recent_alerts)}"
    )
