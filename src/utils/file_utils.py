"""
Утилиты для работы с файлами: хеш (SHA-256), безопасное сохранение во временную директорию,
безопасное удаление, определение MIME по содержимому.
"""
from __future__ import annotations

import hashlib
import mimetypes
import os
import secrets
import tempfile
from pathlib import Path
from typing import BinaryIO, Optional, Union

try:
    import filetype
except ImportError:
    filetype = None  # type: ignore[assignment]

from src.config import config


def compute_file_hash(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """
    Вычисляет SHA-256 хеш файла по пути.
    Чтение чанками для больших файлов.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Файл не найден: {path}")
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_bytes_hash(data: bytes) -> str:
    """SHA-256 хеш от байтов (например, содержимое файла в памяти)."""
    return hashlib.sha256(data).hexdigest()


def get_mime_type(
    file_path: Optional[Union[str, Path]] = None,
    data: Optional[bytes] = None,
) -> Optional[str]:
    """
    Определяет MIME-тип по содержимому (magic bytes), при неудаче — по расширению.
    Передайте file_path или data (первые байты достаточно для filetype).
    """
    mime = None
    if filetype is not None:
        if data is not None:
            kind = filetype.guess(data)
            if kind is not None:
                mime = kind.mime
        if mime is None and file_path is not None:
            path = Path(file_path)
            if path.is_file():
                with open(path, "rb") as f:
                    head = f.read(261)  # filetype достаточно первых байт
                kind = filetype.guess(head)
                if kind is not None:
                    mime = kind.mime
    if mime is None and file_path is not None:
        guessed, _ = mimetypes.guess_type(str(file_path))
        mime = guessed
    return mime


def safe_save_to_temp(
    source: Union[str, Path, BinaryIO, bytes],
    prefix: str = "scan_",
    suffix: str = "",
) -> Path:
    """
    Сохраняет файл во временную директорию (config.UPLOADS_DIR) с уникальным именем.
    source: путь к файлу, файлоподобный объект или bytes.
    Возвращает Path сохранённого файла.
    """
    base_dir = Path(config.UPLOADS_DIR)
    base_dir.mkdir(parents=True, exist_ok=True)
    # Имя: prefix + случайная строка + suffix (расширение можно передать в suffix)
    name = prefix + secrets.token_hex(8) + suffix
    dest = base_dir / name

    if isinstance(source, (str, Path)):
        path = Path(source)
        if not path.is_file():
            raise FileNotFoundError(f"Файл не найден: {path}")
        with open(path, "rb") as f:
            data = f.read()
    elif isinstance(source, bytes):
        data = source
    else:
        # file-like
        data = source.read()

    with open(dest, "wb") as f:
        f.write(data)
    return dest.resolve()


def safe_delete(file_path: Union[str, Path]) -> bool:
    """
    Безопасно удаляет файл. Не выбрасывает исключение, если файла нет или нет прав.
    Returns True, если файл был удалён, False иначе.
    """
    try:
        path = Path(file_path).resolve()
        if not path.is_file():
            return False
        # Запрет удаления вне разрешённых каталогов (UPLOADS_DIR, TEMP_DIR)
        allowed = (
            Path(config.UPLOADS_DIR).resolve(),
            Path(config.TEMP_DIR).resolve(),
        )
        under_allowed = False
        for d in allowed:
            try:
                path.relative_to(d)
                under_allowed = True
                break
            except ValueError:
                continue
        if not under_allowed:
            return False
        path.unlink()
        return True
    except OSError:
        return False


def get_file_size(file_path: Union[str, Path]) -> int:
    """Возвращает размер файла в байтах. При ошибке — 0."""
    try:
        return Path(file_path).stat().st_size
    except OSError:
        return 0
