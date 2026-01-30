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
    
    # Telegram Bot
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    
    # VirusTotal API
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # OpenRouter API
    OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
    OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    
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
        _placeholder = ("your_telegram_bot_token_here", "your_virustotal_api_key_here")
        def _empty(val: str) -> bool:
            v = (val or "").strip()
            return not v or v in _placeholder

        missing = []
        if _empty(cls.TELEGRAM_BOT_TOKEN):
            missing.append("TELEGRAM_BOT_TOKEN")
        if _empty(cls.VIRUSTOTAL_API_KEY):
            missing.append("VIRUSTOTAL_API_KEY")
        # OpenRouter понадобится на этапе интеграции LLM (позже).

        if missing:
            return False, (
                f"В файле .env не заданы: {', '.join(missing)}. "
                f"Откройте .env в корне проекта и укажите реальные значения (шаблон — .env.example)."
            )
        
        return True, None
    
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
