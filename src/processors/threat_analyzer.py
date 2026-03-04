"""
Модуль анализа угроз: подготовка данных для LLM, вызов анализа, парсинг ответа,
определение финального статуса и форматирование результата для пользователя.
LLM выступает аналитическим слоем; финальные решения о безопасности не принимает.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from src.config import config
from src.integrations.llm_client import (
    LLMClient,
    LLMError,
    vt_summary_from_result,
)

logger = logging.getLogger(__name__)

# Эмодзи по уровню риска (roadmap: 🟢 безопасно, 🟡 подозрительно, 🔴 опасно)
STATUS_EMOJI = {
    "clean": "🟢",
    "suspicious": "🟡",
    "phishing": "🔴",
    "malware": "🔴",
    "scam": "🔴",
}
STATUS_LABEL = {
    "clean": "Safe",
    "suspicious": "Suspicious",
    "phishing": "Dangerous",
    "malware": "Dangerous",
    "scam": "Dangerous",
}


def _get_vt_stats(vt_result: dict[str, Any]) -> dict[str, int]:
    """Извлекает агрегированные VT-статистики из разных форматов ответа."""
    data = vt_result.get("data") if isinstance(vt_result, dict) else None
    attrs = (data or {}).get("attributes", {}) if isinstance(data, dict) else {}
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    if not isinstance(stats, dict):
        stats = {}
    return {
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
    }


def _analysis_from_vt_only(vt_result: dict[str, Any]) -> dict[str, Any]:
    """
    Базовый анализ без LLM: классифицирует угрозу по статистике VT.
    Используется как fallback, когда LLM отключен/недоступен.
    """
    stats = _get_vt_stats(vt_result)
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]

    if malicious >= 3:
        threat_type = "phishing"
        risk_level = "high"
        explanation = f"VirusTotal: malicious={malicious}, suspicious={suspicious}."
    elif malicious > 0 or suspicious >= 2:
        threat_type = "suspicious"
        risk_level = "medium"
        explanation = f"VirusTotal: malicious={malicious}, suspicious={suspicious}."
    else:
        threat_type = "clean"
        risk_level = "low"
        explanation = "VirusTotal did not detect explicit threat indicators."

    return {
        "threat_type": threat_type,
        "risk_level": risk_level,
        "explanation": explanation,
        "analysis_data": {"mode": "vt_only", "stats": stats},
    }


def prepare_analysis_data(
    scan_type: str,
    object_description: str,
    vt_result: dict[str, Any],
    extra_context: Optional[str] = None,
) -> dict[str, Any]:
    """
    Подготавливает структурированные данные для отправки в LLM.
    Формирует сводку VirusTotal и собирает все поля в один словарь.
    """
    vt_summary = vt_summary_from_result(vt_result, "file" if scan_type == "file" else "url")
    return {
        "scan_type": scan_type,
        "object_description": object_description,
        "vt_summary": vt_summary,
        "extra_context": extra_context,
    }


def analyze(
    scan_type: str,
    object_description: str,
    vt_summary: str,
    extra_context: Optional[str] = None,
) -> dict[str, Any]:
    """
    Отправляет данные в LLM для анализа и возвращает валидированный результат.

    Returns:
        dict с ключами: threat_type, risk_level, explanation, analysis_data.

    Raises:
        LLMError: при ошибке API или невалидном ответе.
    """
    if not config.is_extended_mode() or not config.has_llm():
        raise LLMError("LLM analysis is disabled: SCAN_MODE != EXTENDED or OPENROUTER_API_KEY is missing.")

    client = LLMClient()
    return client.analyze(
        scan_type=scan_type,
        object_description=object_description,
        vt_summary=vt_summary,
        extra_context=extra_context,
    )


def analyze_from_vt_result(
    scan_type: str,
    object_description: str,
    vt_result: dict[str, Any],
    extra_context: Optional[str] = None,
) -> dict[str, Any]:
    """
    Подготавливает данные из результата VirusTotal и выполняет LLM-анализ.
    Удобная обёртка: prepare_analysis_data + analyze.
    """
    data = prepare_analysis_data(
        scan_type=scan_type,
        object_description=object_description,
        vt_result=vt_result,
        extra_context=extra_context,
    )
    if not config.is_extended_mode() or not config.has_llm():
        return _analysis_from_vt_only(vt_result)

    try:
        return analyze(
            scan_type=data["scan_type"],
            object_description=data["object_description"],
            vt_summary=data["vt_summary"],
            extra_context=data.get("extra_context"),
        )
    except LLMError:
        logger.warning("LLM is unavailable, falling back to VT-only analysis.")
        return _analysis_from_vt_only(vt_result)


def get_final_threat_status(analysis: dict[str, Any]) -> tuple[str, str]:
    """
    Определяет финальный статус угрозы для отображения по результату LLM.
    LLM не принимает финальных решений — статус используется только для UX.

    Returns:
        (emoji, label) — например ("🟢", "Безопасно") или ("🔴", "Опасно").
    """
    threat_type = (analysis.get("threat_type") or "suspicious").strip().lower()
    risk_level = (analysis.get("risk_level") or "medium").strip().lower()

    emoji = STATUS_EMOJI.get(threat_type, "🟡")
    label = STATUS_LABEL.get(threat_type, "Suspicious")

    # Повышаем до 🔴, если high risk и не clean
    if threat_type != "clean" and risk_level == "high":
        emoji = "🔴"
        label = "Dangerous"

    return emoji, label


def format_result_for_user(analysis: dict[str, Any]) -> str:
    """
    Форматирует результат проверки для отправки пользователю: эмодзи, статус и объяснение.
    Коротко и понятно (принципы «Пиши, сокращай»).
    """
    emoji, label = get_final_threat_status(analysis)
    explanation = (analysis.get("explanation") or "").strip()

    lines = [f"{emoji} {label}"]
    if explanation:
        lines.append("")
        lines.append(explanation)
    return "\n".join(lines)
