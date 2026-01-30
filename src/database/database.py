"""
Модуль работы с SQLite: схема, инициализация, CRUD для пользователей,
сканов, результатов VirusTotal, LLM-анализа и файлов.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

from src.config import config

def _get_db_path() -> Path:
    """Возвращает абсолютный путь к файлу БД."""
    root = config.PROJECT_ROOT
    path = config.DATABASE_PATH
    if not Path(path).is_absolute():
        path = root / path
    return Path(path).resolve()


# Схема таблиц
SCHEMA = """
-- Пользователи (по хешу Telegram ID)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

-- Проверки (одна запись = одна проверка)
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    scan_type TEXT NOT NULL CHECK(scan_type IN ('url', 'file', 'voice')),
    object_hash TEXT,
    status TEXT NOT NULL CHECK(status IN ('pending', 'scanning', 'completed', 'error')),
    created_at TEXT NOT NULL
);

-- Результаты VirusTotal (кэш по object_hash)
CREATE TABLE IF NOT EXISTS virustotal_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    object_hash TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK(object_type IN ('url', 'file')),
    virustotal_data TEXT NOT NULL,
    cached_at TEXT NOT NULL
);

-- Результаты LLM-анализа (один к одному со сканом)
CREATE TABLE IF NOT EXISTS llm_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL UNIQUE REFERENCES scans(id),
    threat_type TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    explanation TEXT,
    analysis_data TEXT,
    created_at TEXT NOT NULL
);

-- Метаданные загруженных файлов
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    mime_type TEXT,
    size INTEGER,
    created_at TEXT NOT NULL
);

-- Индексы для истории и кэша
CREATE INDEX IF NOT EXISTS idx_scans_user_created ON scans(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_scans_object_hash ON scans(object_hash);
CREATE INDEX IF NOT EXISTS idx_vt_object_hash ON virustotal_results(object_hash);
CREATE INDEX IF NOT EXISTS idx_vt_scan_id ON virustotal_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_files_scan_id ON files(scan_id);
"""


@contextmanager
def get_connection():
    """Контекстный менеджер для подключения к БД."""
    path = _get_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Создаёт таблицы и индексы, если их ещё нет."""
    with get_connection() as conn:
        conn.executescript(SCHEMA)


# --- Пользователи ---

def create_user(telegram_id_hash: str) -> int:
    """Создаёт пользователя по хешу Telegram ID. Возвращает id. При конфликте возвращает id существующего."""
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (telegram_id_hash, created_at) VALUES (?, datetime('now'))",
            (telegram_id_hash,),
        )
        row = conn.execute(
            "SELECT id FROM users WHERE telegram_id_hash = ?",
            (telegram_id_hash,),
        ).fetchone()
        return row["id"]


def get_or_create_user(telegram_id_hash: str) -> int:
    """Возвращает id пользователя по хешу; при отсутствии создаёт и возвращает новый id."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE telegram_id_hash = ?",
            (telegram_id_hash,),
        ).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO users (telegram_id_hash, created_at) VALUES (?, datetime('now'))",
            (telegram_id_hash,),
        )
        return cur.lastrowid


def get_user_by_hash(telegram_id_hash: str) -> Optional[int]:
    """Возвращает id пользователя по хешу Telegram ID или None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE telegram_id_hash = ?",
            (telegram_id_hash,),
        ).fetchone()
        return row["id"] if row else None


# --- Сканы ---

def create_scan(
    user_id: int,
    scan_type: str,
    object_hash: Optional[str] = None,
    status: str = "pending",
) -> int:
    """Создаёт запись скана. Возвращает id."""
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO scans (user_id, scan_type, object_hash, status, created_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (user_id, scan_type, object_hash or None, status),
        )
        return cur.lastrowid


def update_scan_status(scan_id: int, status: str) -> None:
    """Обновляет статус скана."""
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status = ? WHERE id = ?",
            (status, scan_id),
        )


def get_scan(scan_id: int) -> Optional[dict[str, Any]]:
    """Возвращает скан по id как словарь или None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, user_id, scan_type, object_hash, status, created_at FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None


# --- VirusTotal ---

def save_virustotal_result(
    scan_id: int,
    object_hash: str,
    object_type: str,
    virustotal_data: dict[str, Any] | str,
) -> int:
    """Сохраняет результат VirusTotal. virustotal_data — dict или JSON-строка. Возвращает id записи."""
    data_str = virustotal_data if isinstance(virustotal_data, str) else json.dumps(virustotal_data)
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO virustotal_results (scan_id, object_hash, object_type, virustotal_data, cached_at)
               VALUES (?, ?, ?, ?, datetime('now'))""",
            (scan_id, object_hash, object_type, data_str),
        )
        return cur.lastrowid


def get_cached_virustotal_result(object_hash: str) -> Optional[dict[str, Any]]:
    """Возвращает последний закэшированный результат VT по object_hash или None."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT virustotal_data, cached_at FROM virustotal_results
               WHERE object_hash = ? ORDER BY cached_at DESC LIMIT 1""",
            (object_hash,),
        ).fetchone()
        if not row:
            return None
        data = row["virustotal_data"]
        try:
            return {"data": json.loads(data), "cached_at": row["cached_at"]}
        except (TypeError, json.JSONDecodeError):
            return {"data": data, "cached_at": row["cached_at"]}


# --- LLM-анализ ---

def save_llm_analysis(
    scan_id: int,
    threat_type: str,
    risk_level: str,
    explanation: Optional[str] = None,
    analysis_data: Optional[dict[str, Any] | str] = None,
) -> int:
    """Сохраняет результат LLM-анализа. analysis_data — dict или JSON-строка. Возвращает id."""
    data_str = None
    if analysis_data is not None:
        data_str = analysis_data if isinstance(analysis_data, str) else json.dumps(analysis_data)
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO llm_analysis (scan_id, threat_type, risk_level, explanation, analysis_data, created_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (scan_id, threat_type, risk_level, explanation or None, data_str),
        )
        return cur.lastrowid


def get_llm_analysis(scan_id: int) -> Optional[dict[str, Any]]:
    """Возвращает запись LLM-анализа по scan_id или None."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT id, scan_id, threat_type, risk_level, explanation, analysis_data, created_at
               FROM llm_analysis WHERE scan_id = ?""",
            (scan_id,),
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("analysis_data"):
            try:
                d["analysis_data"] = json.loads(d["analysis_data"])
            except (TypeError, json.JSONDecodeError):
                pass
        return d


# --- Файлы ---

def save_file(
    scan_id: int,
    file_path: str,
    file_hash: str,
    mime_type: Optional[str] = None,
    size: Optional[int] = None,
) -> int:
    """Сохраняет метаданные файла. Возвращает id."""
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO files (scan_id, file_path, file_hash, mime_type, size, created_at)
               VALUES (?, ?, ?, ?, ?, datetime('now'))""",
            (scan_id, file_path, file_hash, mime_type, size),
        )
        return cur.lastrowid


def get_file_by_scan(scan_id: int) -> Optional[dict[str, Any]]:
    """Возвращает запись о файле по scan_id (одна запись на скан) или None."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, scan_id, file_path, file_hash, mime_type, size, created_at FROM files WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
        return dict(row) if row else None


def delete_file_record(file_id: int) -> None:
    """Удаляет запись о файле из БД (сам файл на диске удаляется отдельно)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))


# --- История проверок ---

def get_scan_history_by_user_and_month(
    user_id: int,
    year: int,
    month: int,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """
    Возвращает список сканов пользователя за указанный месяц.
    Год и месяц в локальном времени (1–12).
    """
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT id, user_id, scan_type, object_hash, status, created_at
               FROM scans
               WHERE user_id = ? AND strftime('%Y', created_at) = ? AND strftime('%m', created_at) = ?
               ORDER BY created_at DESC
               LIMIT ? OFFSET ?""",
            (user_id, str(year), f"{month:02d}", limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def get_months_with_scans(user_id: int) -> list[tuple[int, int]]:
    """Возвращает список (year, month) пар, за которые у пользователя есть сканы."""
    with get_connection() as conn:
        rows = conn.execute(
            """SELECT DISTINCT strftime('%Y', created_at) AS y, strftime('%m', created_at) AS m
               FROM scans WHERE user_id = ? ORDER BY y DESC, m DESC""",
            (user_id,),
        ).fetchall()
        return [(int(r["y"]), int(r["m"])) for r in rows if r["y"] and r["m"]]


def get_scan_with_details(scan_id: int) -> Optional[dict[str, Any]]:
    """Возвращает скан с подтянутыми VT, LLM и файлом (если есть) для детального просмотра."""
    scan = get_scan(scan_id)
    if not scan:
        return None
    scan["virustotal_result"] = None
    scan["llm_analysis"] = get_llm_analysis(scan_id)
    scan["file"] = get_file_by_scan(scan_id)
    with get_connection() as conn:
        vt_row = conn.execute(
            "SELECT virustotal_data, cached_at FROM virustotal_results WHERE scan_id = ? LIMIT 1",
            (scan_id,),
        ).fetchone()
        if vt_row:
            try:
                scan["virustotal_result"] = {
                    "data": json.loads(vt_row["virustotal_data"]),
                    "cached_at": vt_row["cached_at"],
                }
            except (TypeError, json.JSONDecodeError):
                scan["virustotal_result"] = {"data": vt_row["virustotal_data"], "cached_at": vt_row["cached_at"]}
    return scan


# --- Очистка данных старше N месяцев ---

def cleanup_old_data(retention_days: Optional[int] = None) -> dict[str, int]:
    """
    Удаляет записи старше retention_days дней.
    По умолчанию — DATA_RETENTION_DAYS из конфига.
    Возвращает счётчики удалённых записей по таблицам.
    """
    days = retention_days if retention_days is not None else config.DATA_RETENTION_DAYS
    cutoff = f"-{days} days"
    deleted = {"scans": 0, "virustotal_results": 0, "llm_analysis": 0, "files": 0}

    with get_connection() as conn:
        # Удаляем сканы старше cutoff и всё связанное (каскадно через FK нет — удаляем вручную)
        cur = conn.execute(
            "SELECT id FROM scans WHERE created_at < datetime('now', ?)",
            (cutoff,),
        )
        old_scan_ids = [r["id"] for r in cur.fetchall()]
        if not old_scan_ids:
            return deleted

        placeholders = ",".join("?" * len(old_scan_ids))
        cur = conn.execute(
            f"DELETE FROM virustotal_results WHERE scan_id IN ({placeholders})",
            old_scan_ids,
        )
        deleted["virustotal_results"] = cur.rowcount
        cur = conn.execute(
            f"DELETE FROM llm_analysis WHERE scan_id IN ({placeholders})",
            old_scan_ids,
        )
        deleted["llm_analysis"] = cur.rowcount
        cur = conn.execute(
            f"DELETE FROM files WHERE scan_id IN ({placeholders})",
            old_scan_ids,
        )
        deleted["files"] = cur.rowcount
        cur = conn.execute(
            f"DELETE FROM scans WHERE id IN ({placeholders})",
            old_scan_ids,
        )
        deleted["scans"] = cur.rowcount

    return deleted
