"""
Обработка проверки ссылок:
- LOCAL: локальный эвристический анализ без внешних API.
- EXTENDED: VirusTotal + (опционально) LLM-анализ с fallback в LOCAL.
"""
from __future__ import annotations

import logging
from typing import Any

from src.config import config
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
from src.security.url_analyzer import analyze_url_heuristic

logger = logging.getLogger(__name__)


def _local_result(url: str, scan_id: int, *, fallback_reason: str | None = None) -> dict[str, Any]:
    """Формирует единый результат локального эвристического анализа."""
    local = analyze_url_heuristic(url)
    reasons = list(local["reasons"])
    if fallback_reason:
        reasons.insert(0, fallback_reason)
    return {
        "success": True,
        "scan_id": scan_id,
        "url": url,
        "risk_score": int(local["risk_score"]),
        "verdict": str(local["verdict"]),
        "reasons": reasons,
    }


def _to_local_shaped_result(url: str, scan_id: int, analysis: dict[str, Any]) -> dict[str, Any]:
    """
    Приводит EXTENDED-анализ (LLM/VT) к единому формату ответа LOCAL:
    risk_score + verdict + reasons.
    """
    risk_level = (analysis.get("risk_level") or "medium").lower()
    threat_type = (analysis.get("threat_type") or "suspicious").lower()
    explanation = (analysis.get("explanation") or "").strip()

    if threat_type == "clean" and risk_level == "low":
        verdict = "clean"
        risk_score = 0
    elif threat_type in {"phishing", "malware", "scam"} or risk_level == "high":
        verdict = "phishing"
        risk_score = 5
    else:
        verdict = "suspicious"
        risk_score = 3

    reasons = [explanation] if explanation else ["Analysis completed in extended mode."]
    return {
        "success": True,
        "scan_id": scan_id,
        "url": url,
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
    }


def process_url(url: str, telegram_id: int) -> dict[str, Any]:
    """
    Проверяет ссылку с учетом SCAN_MODE:
    - LOCAL: локальный анализатор;
    - EXTENDED: VirusTotal + (опционально) LLM, при недоступности ключей fallback в LOCAL.

    Returns:
        success (bool), при success: url, risk_score, verdict, reasons, scan_id;
        при ошибке: error_message.
    """
    ok, err = validate_url(url)
    if not ok:
        return {"success": False, "error_message": err or "Invalid URL format."}

    url_hash = hash_string_for_storage(url)
    user_id = get_or_create_user(hash_telegram_id(telegram_id))
    scan_id = create_scan(user_id, "url", url_hash, status="scanning")

    # Режим LOCAL не использует внешние API.
    if config.is_local_mode():
        update_scan_status(scan_id, "completed")
        return _local_result(url, scan_id)

    # Режим EXTENDED без ключа VT автоматически переходит в LOCAL.
    if not config.has_virustotal():
        logger.info("EXTENDED mode without VIRUSTOTAL_API_KEY, fallback to LOCAL")
        update_scan_status(scan_id, "completed")
        return _local_result(
            url,
            scan_id,
            fallback_reason="External VirusTotal analysis is unavailable. Local heuristic fallback was applied.",
        )

    try:
        vt_client = VirusTotalClient(
            cache_get=get_cached_virustotal_result,
            cache_save=save_virustotal_result,
        )
        vt_result = vt_client.scan_url(url, object_hash=url_hash, scan_id=scan_id)
    except VirusTotalRateLimitError as e:
        logger.warning("VirusTotal rate limit for url: %s. Fallback to LOCAL", e)
        update_scan_status(scan_id, "completed")
        return _local_result(
            url,
            scan_id,
            fallback_reason="VirusTotal rate limit reached. Local heuristic fallback was applied.",
        )
    except VirusTotalError as e:
        logger.warning("VirusTotal error for url: %s", e)
        logger.exception("VirusTotal traceback; fallback to LOCAL")
        update_scan_status(scan_id, "completed")
        return _local_result(
            url,
            scan_id,
            fallback_reason="Extended VirusTotal analysis failed. Local heuristic fallback was applied.",
        )

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
        logger.exception("LLM traceback; fallback to LOCAL shape from VT data")
        # Даже при ошибке LLM сохраняем базовый результат на основе VT.
        analysis = {
            "threat_type": "suspicious",
            "risk_level": "medium",
            "explanation": "LLM analysis is unavailable; a baseline VirusTotal assessment was used.",
            "analysis_data": {},
        }

    save_llm_analysis(
        scan_id=scan_id,
        threat_type=analysis["threat_type"],
        risk_level=analysis["risk_level"],
        explanation=analysis.get("explanation"),
        analysis_data=analysis.get("analysis_data"),
    )
    update_scan_status(scan_id, "completed")

    return _to_local_shaped_result(url, scan_id, analysis)
