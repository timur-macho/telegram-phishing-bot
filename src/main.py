"""
Главный файл для запуска Telegram бота.
"""
import logging
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


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик команды /start."""
    user = update.effective_user
    logger.info(f"User {user.id} started the bot")
    
    welcome_message = (
        "👋 Привет! Я помогу проверить ссылки и файлы на безопасность.\n\n"
        "Отправь мне ссылку, файл или голосовое сообщение для проверки."
    )
    
    await update.message.reply_text(welcome_message)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик текстовых сообщений."""
    logger.info(f"Received text message from user {update.effective_user.id}")
    await update.message.reply_text("Функционал проверки ссылок будет реализован в следующих этапах.")


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик документов."""
    logger.info(f"Received document from user {update.effective_user.id}")
    await update.message.reply_text("Функционал проверки файлов будет реализован в следующих этапах.")


async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик голосовых сообщений."""
    logger.info(f"Received voice message from user {update.effective_user.id}")
    await update.message.reply_text("Функционал обработки голосовых сообщений будет реализован в следующих этапах.")


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обработчик ошибок."""
    logger.error(f"Exception while handling an update: {context.error}", exc_info=context.error)
    
    if update and update.effective_message:
        await update.effective_message.reply_text(
            "Произошла ошибка при обработке запроса. Попробуйте позже."
        )


def main() -> None:
    """Главная функция для запуска бота."""
    # Проверяем конфигурацию
    is_valid, error = config.validate()
    if not is_valid:
        logger.error(f"Configuration error: {error}")
        sys.exit(1)
    
    # Создаем необходимые директории
    config.ensure_directories()

    # Инициализируем БД (таблицы и индексы)
    init_db()

    # Создаем приложение
    application = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()
    
    # Регистрируем обработчики
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.VOICE, handle_voice))
    
    # Обработчик ошибок
    application.add_error_handler(error_handler)
    
    # Запускаем бота
    logger.info("Bot is starting...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
