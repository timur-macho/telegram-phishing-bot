"""Main entry point for launching the Telegram bot (URL-only mode)."""
import asyncio
import logging
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

from src.config import config
from src.database import init_db
from src.processors.link_processor import process_url as process_url_sync
from src.security.rate_limiter import rate_limiter

config.ensure_directories()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=getattr(logging, config.LOG_LEVEL),
    handlers=[
        logging.FileHandler(Path(config.LOG_DIR) / "bot.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE,
)


def _format_scan_result(result: dict) -> str:
    """Format URL scan results for user-facing Telegram responses."""
    if not result.get("success"):
        return result.get("error_message", "An unexpected error occurred.")

    if "verdict" in result and "risk_score" in result:
        url = (result.get("url") or "").strip()
        verdict = str(result.get("verdict") or "suspicious").upper()
        risk_score = int(result.get("risk_score") or 0)
        reasons = result.get("reasons") or []

        lines = [
            "URL Analysis",
            "",
            f"Link: {url}",
            "",
            f"Risk Score: {risk_score}",
            "",
            f"Verdict: {verdict}",
            "",
            "Reasons:",
        ]
        if reasons:
            lines.extend([f"- {str(reason)}" for reason in reasons])
        else:
            lines.append("- No explicit indicators found.")
        return "\n".join(lines)

    return "Analysis completed, but no structured URL report was produced."


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command."""
    user = update.effective_user
    logger.info("User %s started the bot", user.id)

    welcome_message = (
        "Welcome to the Phishing Detection Bot.\n\n"
        "Send a URL and I will analyze it using heuristic phishing detection techniques "
        "to identify suspicious or malicious links."
    )
    await update.message.reply_text(welcome_message)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle text messages: extract one URL and run analysis."""
    user = update.effective_user
    text = (update.message.text or "").strip()
    logger.info("Received text from user %s", user.id)

    urls = URL_PATTERN.findall(text)
    if not urls:
        await update.message.reply_text("Please send exactly one URL for analysis (http or https).")
        return
    if len(urls) > 1:
        await update.message.reply_text("Please send only one URL at a time.")
        return
    url = urls[0].rstrip(".,;:!?)")

    allowed, limit_msg = rate_limiter.is_allowed(user.id)
    if not allowed:
        await update.message.reply_text(limit_msg or "Rate limit exceeded. Please wait before trying again.")
        return
    rate_limiter.record_request(user.id)

    status_msg = await update.message.reply_text("Running URL analysis...")
    try:
        result = await asyncio.to_thread(process_url_sync, url, user.id)
    except Exception as e:
        logger.exception("Link processing error: %s", e)
        await status_msg.edit_text(
            "URL analysis failed due to an internal error. Please try again later. "
            "See logs/bot.log for details."
        )
        return

    if not result.get("success"):
        logger.warning("Link check failed for user %s: %s", user.id, result.get("error_message"))
    reply = _format_scan_result(result)
    await status_msg.edit_text(reply)


async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Global Telegram update error handler."""
    logger.error("Exception while handling an update: %s", context.error, exc_info=context.error)

    if update and update.effective_message:
        await update.effective_message.reply_text(
            "An internal error occurred while processing your request. Please try again later."
        )


def main() -> None:
    """Run the bot."""
    is_valid, error = config.validate()
    if not is_valid:
        logger.error("Configuration error: %s", error)
        sys.exit(1)

    config.ensure_directories()
    init_db()

    application = Application.builder().token(config.TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    application.add_error_handler(error_handler)

    logger.info("Bot is starting in URL-only mode...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
