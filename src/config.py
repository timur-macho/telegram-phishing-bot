"""
Модуль для загрузки и управления конфигурацией приложения.
Все настройки загружаются из переменных окружения.
"""
import os
import shutil
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Корень проекта (каталог, где лежат .env и .env.example)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = PROJECT_ROOT / ".env"
ENV_EXAMPLE_PATH = PROJECT_ROOT / ".env.example"

# Создаём .env из шаблона, если его нет
if not ENV_PATH.exists() and ENV_EXAMPLE_PATH.exists():
    shutil.copy(ENV_EXAMPLE_PATH, ENV_PATH)

# Загружаем переменные из .env в корне проекта
load_dotenv(ENV_PATH)


class Config:
    """Класс для хранения конфигурации приложения."""

    PROJECT_ROOT: Path = PROJECT_ROOT

    # Telegram Bot
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    
    # VirusTotal API
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # OpenRouter API
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")

    # Scan mode: LOCAL (no external APIs) or EXTENDED (VirusTotal + LLM when available)
    SCAN_MODE: str = os.getenv("SCAN_MODE", "LOCAL").strip().upper() or "LOCAL"
    
    # Database
    DATABASE_PATH: str = os.getenv("DATABASE_PATH", "./data/bot.db")
    
    # File Configuration
    MAX_FILE_SIZE: int = int(os.getenv("MAX_FILE_SIZE", "67108864"))  # 64 MB
    TEMP_DIR: str = os.getenv("TEMP_DIR", "./temp")
    UPLOADS_DIR: str = os.getenv("UPLOADS_DIR", "./temp/uploads")
    
    # Rate Limiting
    RATE_LIMIT_PER_USER: int = int(os.getenv("RATE_LIMIT_PER_USER", "10"))
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "3600"))  # 1 hour
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_DIR: str = os.getenv("LOG_DIR", "./logs")
    
    # Data Retention
    DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", "180"))
    
    @classmethod
    def validate(cls) -> tuple[bool, Optional[str]]:
        """
        Проверяет, что все обязательные переменные окружения установлены.
        
        Returns:
            tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        # Плейсхолдеры из .env.example считаем пустыми
        _placeholders = (
            "your_telegram_bot_token_here",
            "your_virustotal_api_key_here",
            "your_openrouter_api_key_here",
        )
        def _empty(val: str) -> bool:
            v = (val or "").strip()
            return not v or v in _placeholders

        missing = []
        if _empty(cls.TELEGRAM_BOT_TOKEN):
            missing.append("TELEGRAM_BOT_TOKEN")
        if cls.SCAN_MODE not in {"LOCAL", "EXTENDED"}:
            return False, "SCAN_MODE must be either LOCAL or EXTENDED."

        if missing:
            env_path = Path(cls.PROJECT_ROOT) / ".env"
            return False, (
                f"Missing required variables in .env: {', '.join(missing)}. "
                f"The application reads variables from .env (not .env.example). "
                f".env path: {env_path.resolve()}. "
                f"If values exist only in .env.example, copy them to .env "
                f"(e.g., copy .env.example .env)."
            )
        
        return True, None

    @classmethod
    def is_local_mode(cls) -> bool:
        """True, если включен локальный режим сканирования."""
        return cls.SCAN_MODE == "LOCAL"

    @classmethod
    def is_extended_mode(cls) -> bool:
        """True, если включен расширенный режим сканирования."""
        return cls.SCAN_MODE == "EXTENDED"

    @classmethod
    def has_virustotal(cls) -> bool:
        """True, если задан ключ VirusTotal."""
        return bool((cls.VIRUSTOTAL_API_KEY or "").strip())

    @classmethod
    def has_llm(cls) -> bool:
        """True, если задан ключ OpenRouter."""
        return bool((cls.OPENROUTER_API_KEY or "").strip())
    
    @classmethod
    def ensure_directories(cls) -> None:
        """Создает необходимые директории, если они не существуют."""
        directories = [
            Path(cls.TEMP_DIR),
            Path(cls.UPLOADS_DIR),
            Path(cls.LOG_DIR),
            Path(cls.DATABASE_PATH).parent,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


# Создаем экземпляр конфигурации
config = Config()
