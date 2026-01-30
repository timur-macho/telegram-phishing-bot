"""
Модуль безопасности: хеширование, валидация URL/файлов, санитизация, защита от prompt-injection.
Соответствует OWASP Top-10 и требованиям проекта (SSRF, валидация входных данных).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Optional
from urllib.parse import urlparse

from src.config import config


# --- Хеширование ---

def hash_telegram_id(telegram_id: int) -> str:
    """
    Хеширует Telegram ID пользователя SHA-256.
    Используется для хранения в БД без раскрытия идентификатора.
    """
    raw = f"tg:{telegram_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def hash_string_for_storage(value: str) -> str:
    """Хеш строки (URL, содержимое) для кэша и идентификации объекта (SHA-256)."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


# --- Валидация URL (формат + SSRF) ---

# Разрешены только HTTP/HTTPS
ALLOWED_URL_SCHEMES = frozenset(("http", "https"))

# Паттерны хостов, которые считаем внутренними/опасными (SSRF)
BLOCKED_HOSTNAME_PATTERNS = re.compile(
    r"^(localhost|127\.|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.|\[)",
    re.IGNORECASE,
)


def _is_private_or_reserved_ip(host: str) -> bool:
    """Проверяет, является ли host приватным/зарезервированным IP (IPv4 или IPv6)."""
    host_clean = host.strip("[]")
    try:
        addr = ipaddress.ip_address(host_clean)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
        )
    except ValueError:
        return False


def validate_url(url: str) -> tuple[bool, Optional[str]]:
    """
    Проверяет URL: формат и защита от SSRF (без перехода по ссылке).
    - Допускаются только http/https.
    - Блокируются localhost, приватные и зарезервированные IP, hostname в скобках [x].
    Returns:
        (True, None) если URL допустим, иначе (False, сообщение об ошибке).
    """
    if not url or not isinstance(url, str):
        return False, "Пустая или некорректная ссылка."
    url = url.strip()
    if len(url) > 2048:
        return False, "Ссылка слишком длинная."
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Некорректный формат ссылки."
    if not parsed.scheme:
        return False, "Укажите протокол (http или https)."
    if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
        return False, "Допускаются только ссылки с протоколом http или https."
    netloc = (parsed.netloc or "").strip()
    if not netloc:
        return False, "В ссылке отсутствует адрес сервера."
    # Блок по имени хоста (localhost, 127..., 10..., и т.д.)
    if BLOCKED_HOSTNAME_PATTERNS.match(netloc):
        return False, "Ссылки на локальные и внутренние адреса проверять нельзя."
    # Если в netloc есть IP (например после разрешения DNS не делаем — только явный IP в URL)
    host = netloc.split(":")[0]
    if _is_private_or_reserved_ip(host):
        return False, "Ссылки на локальные и внутренние адреса проверять нельзя."
    return True, None


# --- Валидация файлов (MIME, размер) ---

# Допустимые MIME-типы для проверки (документы, архивы, изображения; без исполняемых)
ALLOWED_MIME_TYPES = frozenset({
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
    "application/x-7z-compressed",
    "text/plain",
    "text/html",
    "text/csv",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
    "image/bmp",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
})

# MIME-типы, которые всегда запрещены (исполняемые, скрипты и т.п.)
BLOCKED_MIME_TYPES = frozenset({
    "application/x-executable",
    "application/x-msdownload",
    "application/x-msi",
    "application/vnd.microsoft.portable-executable",
    "application/x-sh",
    "application/x-shellscript",
    "text/x-python",
    "application/javascript",
    "application/x-javascript",
    "application/x-php",
    "application/x-httpd-php",
})


def check_file_size(size_bytes: int, max_size: Optional[int] = None) -> tuple[bool, Optional[str]]:
    """
    Проверяет, не превышает ли размер файла лимит.
    По умолчанию используется config.MAX_FILE_SIZE.
    """
    max_size = max_size if max_size is not None else config.MAX_FILE_SIZE
    if size_bytes < 0:
        return False, "Некорректный размер файла."
    if size_bytes > max_size:
        mb = max_size / (1024 * 1024)
        return False, f"Файл слишком большой. Максимум — {mb:.0f} МБ."
    return True, None


def validate_file_mime(mime_type: Optional[str], size_bytes: int) -> tuple[bool, Optional[str]]:
    """
    Проверяет MIME-тип и размер файла.
    Returns:
        (True, None) если файл допустим, иначе (False, сообщение об ошибке).
    """
    ok, err = check_file_size(size_bytes)
    if not ok:
        return False, err
    if not mime_type or not mime_type.strip():
        return False, "Не удалось определить тип файла."
    mime = mime_type.strip().lower().split(";")[0]
    if mime in BLOCKED_MIME_TYPES:
        return False, "Этот тип файлов (исполняемый/скрипт) проверять нельзя."
    if mime not in ALLOWED_MIME_TYPES:
        return False, "Этот тип файла пока не поддерживается для проверки."
    return True, None


# --- Санитизация входных данных ---

# Максимальная длина текстового ввода (символы)
MAX_INPUT_LENGTH = 10_000

# Удаляем управляющие символы
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_input(text: str) -> str:
    """
    Санитизация пользовательского ввода: обрезка длины, удаление управляющих символов.
    Не выполняет HTML-экранирование (это делается при выводе в нужном контексте).
    """
    if not isinstance(text, str):
        return ""
    s = text.strip()
    s = CONTROL_CHARS.sub("", s)
    if len(s) > MAX_INPUT_LENGTH:
        s = s[:MAX_INPUT_LENGTH]
    return s


# --- Защита от prompt-injection для LLM ---

# Паттерны, которые могут использоваться для смены роли/инструкций в промпте
INSTRUCTION_LIKE_PATTERNS = re.compile(
    r"\b(ignore|forget|disregard|override|new\s+instruction|system\s*:|\bact\s+as\s+|\byou\s+are\s+now\s+)\b",
    re.IGNORECASE,
)
# Опасные разделители, часто используемые в промптах
DELIMITER_PATTERNS = [
    re.compile(r"\[INST\]|\[/INST\]|</s>|<\|[a-z_]+\|>", re.IGNORECASE),
    re.compile(r"^(user|assistant|system)\s*:\s*", re.IGNORECASE | re.MULTILINE),
]


def sanitize_for_llm(user_content: str) -> str:
    """
    Подготовка пользовательского контента перед вставкой в промпт LLM.
    Снижает риск prompt-injection: обрезка длины, удаление управляющих символов,
    нейтрализация типичных инструкций и разделителей ролей.
    Не гарантирует полную защиту — LLM не принимает финальных решений о безопасности.
    """
    if not isinstance(user_content, str):
        return ""
    s = user_content.strip()
    s = CONTROL_CHARS.sub("", s)
    if len(s) > MAX_INPUT_LENGTH:
        s = s[:MAX_INPUT_LENGTH]
    # Удаляем маркеры ролей/инструкций
    for pat in DELIMITER_PATTERNS:
        s = pat.sub(" ", s)
    # Заменяем подозрительные «инструкции» на пробел, чтобы не дать переписать контекст
    s = INSTRUCTION_LIKE_PATTERNS.sub(" ", s)
    return " ".join(s.split())
