from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import signal
from pathlib import Path

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError

from secopsbuddy.bot.handlers import build_router
from secopsbuddy.bot.notifier import render_event
from secopsbuddy.bot.settings import BotSettings
from secopsbuddy.bot.state import BotRuntimeState
from secopsbuddy.config import ConfigError, load_config
from secopsbuddy.utils.time_utils import utc_now_iso


BOT_LOGGER_NAME = "secopsbuddy.bot"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="secopsbuddy-bot-worker")
    parser.add_argument("--config", default=None, help="Путь к YAML-конфигу")
    parser.add_argument("--env-file", default=".env", help="Путь к .env")
    return parser.parse_args(argv)


def setup_bot_logging(log_file: str, error_log_file: str) -> logging.Logger:
    logger = logging.getLogger(BOT_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handler = logging.FileHandler(log_path, encoding="utf-8")
    log_handler.setLevel(logging.INFO)
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)

    error_path = Path(error_log_file)
    error_path.parent.mkdir(parents=True, exist_ok=True)
    error_handler = logging.FileHandler(error_path, encoding="utf-8")
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(formatter)
    logger.addHandler(error_handler)

    return logger


async def run_worker(config_path: str | None, env_file: str) -> int:
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        print(f"[ОШИБКА] Не удалось загрузить конфиг для бота: {exc}")
        return 2

    logger = setup_bot_logging(config.bot_log_file, config.bot_error_log_file)

    try:
        settings = BotSettings.from_env(config.bot_events_file, env_file)
    except ValueError as exc:
        logger.error("Ошибка .env: %s", exc)
        return 2

    state = BotRuntimeState()
    bot = Bot(
        token=settings.token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher()
    dp.include_router(build_router(state, settings))

    stop_event = asyncio.Event()
    _register_signal_handlers(stop_event)

    logger.info("Бот инициализирован")
    await bot.delete_webhook(drop_pending_updates=False)

    await _broadcast_text(
        bot,
        settings,
        state,
        (
            "🤖 <b>SecOps Buddy Bot запущен</b>\n"
            f"Время: <code>{utc_now_iso()}</code>"
        ),
        category="lifecycle",
        logger=logger,
    )

    polling_task = asyncio.create_task(
        dp.start_polling(
            bot,
            handle_signals=False,
            allowed_updates=dp.resolve_used_update_types(),
        )
    )
    stream_task = asyncio.create_task(
        _stream_events(
            bot=bot,
            settings=settings,
            state=state,
            stop_event=stop_event,
            logger=logger,
        )
    )
    stop_task = asyncio.create_task(stop_event.wait())

    done, pending = await asyncio.wait(
        {polling_task, stream_task, stop_task},
        return_when=asyncio.FIRST_COMPLETED,
    )

    if stop_task in done:
        logger.info("Получен сигнал остановки")
    elif polling_task in done:
        logger.warning("Polling завершился раньше ожидаемого")
    elif stream_task in done:
        logger.warning("Поток чтения событий завершился раньше ожидаемого")

    stop_event.set()
    dp.stop_polling()

    for task in pending:
        task.cancel()

    await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.gather(*done, return_exceptions=True)

    await _broadcast_text(
        bot,
        settings,
        state,
        (
            "🛑 <b>SecOps Buddy Bot остановлен</b>\n"
            f"Время: <code>{utc_now_iso()}</code>"
        ),
        category="lifecycle",
        logger=logger,
    )

    await bot.session.close()
    logger.info("Бот корректно остановлен")
    return 0


async def _stream_events(
    bot: Bot,
    settings: BotSettings,
    state: BotRuntimeState,
    stop_event: asyncio.Event,
    logger: logging.Logger,
) -> None:
    path = Path(settings.events_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)

    with path.open("r", encoding="utf-8") as source:
        source.seek(0, 2)
        while not stop_event.is_set():
            line = source.readline()
            if not line:
                await asyncio.sleep(1)
                continue

            stripped = line.strip()
            if not stripped:
                continue

            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                logger.warning("Некорректная строка события: %s", stripped)
                continue

            rendered = render_event(event)
            if rendered is None:
                continue

            text, keyboard, category = rendered
            if category in {"alert", "error", "mitigation", "action"}:
                state.add_alert(_strip_html(text))

            await _broadcast_text(
                bot=bot,
                settings=settings,
                state=state,
                text=text,
                category=category,
                logger=logger,
                reply_markup=keyboard,
            )


async def _broadcast_text(
    bot: Bot,
    settings: BotSettings,
    state: BotRuntimeState,
    text: str,
    category: str,
    logger: logging.Logger,
    reply_markup: object | None = None,
) -> None:
    for chat_id in settings.allowed_chat_ids:
        if category in {"alert", "mitigation", "action"} and state.is_muted(chat_id):
            continue

        try:
            await bot.send_message(
                chat_id=chat_id,
                text=text,
                disable_web_page_preview=True,
                reply_markup=reply_markup,
            )
        except TelegramForbiddenError:
            logger.error("Бот заблокирован пользователем chat_id=%s", chat_id)
        except TelegramBadRequest as exc:
            logger.error("Ошибка отправки в chat_id=%s: %s", chat_id, exc)
        except Exception as exc:
            logger.error("Неожиданная ошибка отправки chat_id=%s: %s", chat_id, exc)


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)


def _register_signal_handlers(stop_event: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            continue


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return asyncio.run(run_worker(args.config, args.env_file))


if __name__ == "__main__":
    raise SystemExit(main())
