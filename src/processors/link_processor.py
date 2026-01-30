"""
Обработка проверки ссылок: валидация URL, VirusTotal, LLM-анализ, сохранение в БД.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from src.database.database import (
    create_scan,
    get_cached_virustotal_result,
    get_or_create_user,
    save_llm_analysis,
    save_virustotal_result,
    update_scan_status,
)
from src.integrations.virustotal_client import (
    VirusTotalClient,
    VirusTotalError,
    VirusTotalRateLimitError,
)
from src.security.security import hash_string_for_storage, hash_telegram_id, validate_url

logger = logging.getLogger(__name__)


def process_url(url: str, telegram_id: int) -> dict[str, Any]:
    """
    Проверяет ссылку: валидация → VirusTotal → LLM → сохранение в БД.

    Returns:
        success (bool), при success: threat_type, risk_level, explanation, scan_id;
        при ошибке: error_message; при rate limit: error_message с текстом лимита.
    """
    ok, err = validate_url(url)
    if not ok:
        return {"success": False, "error_message": err or "Некорректная ссылка."}

    url_hash = hash_string_for_storage(url)
    user_id = get_or_create_user(hash_telegram_id(telegram_id))
    scan_id = create_scan(user_id, "url", url_hash, status="scanning")

    try:
        vt_client = VirusTotalClient(
            cache_get=get_cached_virustotal_result,
            cache_save=save_virustotal_result,
        )
        vt_result = vt_client.scan_url(url, object_hash=url_hash, scan_id=scan_id)
    except VirusTotalRateLimitError as e:
        update_scan_status(scan_id, "error")
        return {"success": False, "error_message": str(e)}
    except VirusTotalError as e:
        logger.warning("VirusTotal error for url: %s", e)
        logger.exception("VirusTotal traceback")
        update_scan_status(scan_id, "error")
        msg = "Сервис проверки временно недоступен. Попробуйте позже."
        if "401" in str(e) or "ключ" in str(e).lower() or "api" in str(e).lower():
            msg += " Проверьте VIRUSTOTAL_API_KEY в .env и логи (logs/bot.log)."
        return {"success": False, "error_message": msg}

    try:
        from src.processors.threat_analyzer import analyze_from_vt_result
        from src.integrations.llm_client import LLMError

        analysis = analyze_from_vt_result(
            scan_type="url",
            object_description=url,
            vt_result=vt_result,
        )
    except LLMError as e:
        logger.warning("LLM error for url: %s", e)
        logger.exception("LLM traceback")
        update_scan_status(scan_id, "error")
        msg = "Анализ временно недоступен. Попробуйте позже."
        if "401" in str(e) or "ключ" in str(e).lower() or "429" in str(e):
            msg += " Проверьте OPENROUTER_API_KEY и OPENROUTER_MODEL в .env, логи: logs/bot.log."
        return {"success": False, "error_message": msg}

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
