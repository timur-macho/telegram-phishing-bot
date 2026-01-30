"""
Обработка проверки файлов: валидация (размер, MIME), VirusTotal, LLM-анализ, сохранение в БД.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from src.database.database import (
    create_scan,
    get_cached_virustotal_result,
    get_or_create_user,
    save_file as save_file_record,
    save_llm_analysis,
    save_virustotal_result,
    update_scan_status,
)
from src.integrations.virustotal_client import (
    VirusTotalClient,
    VirusTotalError,
    VirusTotalRateLimitError,
)
from src.security.security import hash_telegram_id, validate_file_mime
from src.utils.file_utils import compute_file_hash, safe_delete

logger = logging.getLogger(__name__)


def process_file(
    file_path: Path,
    file_size: int,
    mime_type: Optional[str],
    telegram_id: int,
) -> dict[str, Any]:
    """
    Проверяет файл: валидация → хеш → VirusTotal (по хешу или загрузка) → LLM → сохранение в БД.
    После обработки файл удаляется из временной директории.

    Returns:
        success (bool), при success: threat_type, risk_level, explanation, scan_id;
        при ошибке: error_message.
    """
    ok, err = validate_file_mime(mime_type, file_size)
    if not ok:
        return {"success": False, "error_message": err or "Файл не подходит для проверки."}

    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error_message": "Файл не найден."}

    try:
        file_hash = compute_file_hash(path)
    except OSError as e:
        logger.exception("Cannot compute file hash")
        return {"success": False, "error_message": "Не удалось прочитать файл."}

    user_id = get_or_create_user(hash_telegram_id(telegram_id))
    scan_id = create_scan(user_id, "file", file_hash, status="scanning")
    save_file_record(
        scan_id=scan_id,
        file_path=str(path.resolve()),
        file_hash=file_hash,
        mime_type=mime_type,
        size=file_size,
    )

    try:
        vt_client = VirusTotalClient(
            cache_get=get_cached_virustotal_result,
            cache_save=save_virustotal_result,
        )
        vt_result = vt_client.scan_file(path, file_hash, scan_id=scan_id)
    except VirusTotalRateLimitError as e:
        update_scan_status(scan_id, "error")
        safe_delete(path)
        return {"success": False, "error_message": str(e)}
    except VirusTotalError as e:
        logger.warning("VirusTotal error for file: %s", e)
        logger.exception("VirusTotal traceback")
        update_scan_status(scan_id, "error")
        safe_delete(path)
        msg = "Сервис проверки временно недоступен. Попробуйте позже."
        if "401" in str(e) or "ключ" in str(e).lower() or "api" in str(e).lower():
            msg += " Проверьте VIRUSTOTAL_API_KEY в .env и логи (logs/bot.log)."
        return {"success": False, "error_message": msg}

    object_desc = f"Файл: {path.name}, MIME: {mime_type or 'unknown'}, hash: {file_hash[:16]}..."

    try:
        from src.processors.threat_analyzer import analyze_from_vt_result
        from src.integrations.llm_client import LLMError

        analysis = analyze_from_vt_result(
            scan_type="file",
            object_description=object_desc,
            vt_result=vt_result,
        )
    except LLMError as e:
        logger.warning("LLM error for file: %s", e)
        logger.exception("LLM traceback")
        update_scan_status(scan_id, "error")
        safe_delete(path)
        msg = "Анализ временно недоступен. Попробуйте позже."
        if "401" in str(e) or "ключ" in str(e).lower() or "429" in str(e):
            msg += " Проверьте OPENROUTER_API_KEY и OPENROUTER_MODEL в .env, логи: logs/bot.log."
        return {"success": False, "error_message": msg}
    finally:
        safe_delete(path)

    save_llm_analysis(
        scan_id=scan_id,
        threat_type=analysis["threat_type"],
        risk_level=analysis["risk_level"],
        explanation=analysis.get("explanation"),
        analysis_data=analysis.get("analysis_data"),
    )
    update_scan_status(scan_id, "completed")

    return {
        "success": True,
        "scan_id": scan_id,
        "threat_type": analysis["threat_type"],
        "risk_level": analysis["risk_level"],
        "explanation": analysis.get("explanation") or "",
    }
