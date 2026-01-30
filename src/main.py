"""
Главный файл для запуска Telegram бота.
"""
import asyncio
import logging
import re
import sys
from pathlib import Path

# Корень проекта в PYTHONPATH при запуске через python src/main.py
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from src.config import config
from src.database import init_db
from src.processors.link_processor import process_url as process_url_sync
from src.processors.file_processor import process_file as process_file_sync
from src.security.rate_limiter import rate_limiter
from src.utils.file_utils import get_mime_type, safe_delete

# Создаём директории (logs, temp и т.д.) до настройки логирования
config.ensure_directories()

# Настройка логирования
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=getattr(logging, config.LOG_LEVEL),
    handlers=[
        logging.FileHandler(Path(config.LOG_DIR) / "bot.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)

# Одна ссылка http(s) в сообщении
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


def _format_scan_result(result: dict) -> str:
    """Форматирует результат проверки для сообщения пользователю (эмодзи + объяснение)."""
    if not result.get("success"):
        return result.get("error_message", "Произошла ошибка.")
    risk = result.get("risk_level", "").lower()
    threat = result.get("threat_type", "").lower()
    explanation = (result.get("explanation") or "").strip()
    if threat == "clean" or risk == "low":
        emoji = "🟢"
        label = "Безопасно"
    elif risk == "high" or threat in ("phishing", "malware", "scam"):
        emoji = "🔴"
        label = "Опасно"
    else:
        emoji = "🟡"
        label = "Подозрительно"
    parts = [f"{emoji} {label}"]
    if explanation:
        parts.append(explanation)
    return "\n\n".join(parts)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик команды /start."""
    user = update.effective_user
    logger.info("User %s started the bot", user.id)

    welcome_message = (
        "👋 Привет! Я помогу проверить ссылки и файлы на безопасность.\n\n"
        "Отправь мне ссылку, файл или голосовое сообщение для проверки."
    )

    await update.message.reply_text(welcome_message)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик текстовых сообщений: извлечение ссылки и проверка."""
    user = update.effective_user
    text = (update.message.text or "").strip()
    logger.info("Received text from user %s", user.id)

    urls = URL_PATTERN.findall(text)
    if not urls:
        await update.message.reply_text("Отправьте одну ссылку для проверки (http или https).")
        return
    if len(urls) > 1:
        await update.message.reply_text("Отправьте только одну ссылку за раз.")
        return
    url = urls[0].rstrip(".,;:!?)")

    allowed, limit_msg = rate_limiter.is_allowed(user.id)
    if not allowed:
        await update.message.reply_text(limit_msg or "Слишком много запросов. Подождите.")
        return
    rate_limiter.record_request(user.id)

    status_msg = await update.message.reply_text("Проверяю ссылку…")
    try:
        result = await asyncio.to_thread(process_url_sync, url, user.id)
    except Exception as e:
        logger.exception("Link processing error: %s", e)
        await status_msg.edit_text("Произошла ошибка при проверке. Попробуйте позже. Подробности в logs/bot.log.")
        return
    if not result.get("success"):
        logger.warning("Link check failed for user %s: %s", user.id, result.get("error_message"))
    reply = _format_scan_result(result)
    await status_msg.edit_text(reply)


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик документов: скачивание во временный каталог и проверка файла."""
    user = update.effective_user
    document = update.message.document
    logger.info("Received document from user %s", user.id)

    allowed, limit_msg = rate_limiter.is_allowed(user.id)
    if not allowed:
        await update.message.reply_text(limit_msg or "Слишком много запросов. Подождите.")
        return
    rate_limiter.record_request(user.id)

    status_msg = await update.message.reply_text("Проверяю файл…")
    file_path = None
    try:
        tg_file = await context.bot.get_file(document.file_id)
        # Сохраняем во временный каталог проекта
        dest_dir = Path(config.UPLOADS_DIR)
        dest_dir.mkdir(parents=True, exist_ok=True)
        safe_name = (document.file_name or "file").replace("..", "_").strip() or "file"
        file_path = dest_dir / f"{document.file_id}_{safe_name}"
        await tg_file.download_to_drive(custom_path=str(file_path))

        file_size = file_path.stat().st_size
        mime_type = get_mime_type(file_path=file_path)

        result = await asyncio.to_thread(
            process_file_sync,
            file_path,
            file_size,
            mime_type,
            user.id,
        )
    except Exception as e:
        logger.exception("File processing error: %s", e)
        if file_path and file_path.is_file():
            safe_delete(file_path)
        await status_msg.edit_text("Произошла ошибка при проверке файла. Попробуйте позже. Подробности в logs/bot.log.")
        return

    if not result.get("success"):
        logger.warning("File check failed for user %s: %s", user.id, result.get("error_message"))
    reply = _format_scan_result(result)
    await status_msg.edit_text(reply)


async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик голосовых сообщений."""
    logger.info("Received voice from user %s", update.effective_user.id)
    await update.message.reply_text(
        "Функционал обработки голосовых сообщений будет реализован в следующих этапах."
    )


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик ошибок."""
    logger.error("Exception while handling an update: %s", context.error, exc_info=context.error)

    if update and update.effective_message:
        await update.effective_message.reply_text(
            "Произошла ошибка при обработке запроса. Попробуйте позже."
        )


def main() -> None:
    """Главная функция для запуска бота."""
    is_valid, error = config.validate()
    if not is_valid:
        logger.error("Configuration error: %s", error)
        sys.exit(1)

    config.ensure_directories()
    init_db()

    application = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.VOICE, handle_voice))
    application.add_error_handler(error_handler)

    logger.info("Bot is starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
