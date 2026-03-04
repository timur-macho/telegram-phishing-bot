"""
Клиент OpenRouter API для анализа угроз: формирование промпта, запрос к LLM,
парсинг и валидация структурированного JSON. LLM выступает аналитическим слоем,
финальные решения о безопасности не принимает.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

import httpx

from src.config import config
from src.security.security import sanitize_for_llm

logger = logging.getLogger(__name__)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
REQUEST_TIMEOUT = 90.0

# Допустимые значения из требований
THREAT_TYPES = frozenset({"phishing", "malware", "scam", "suspicious", "clean"})
RISK_LEVELS = frozenset({"low", "medium", "high"})


class LLMError(Exception):
    """Ошибка при работе с LLM API."""
    pass


class LLMResponseError(LLMError):
    """Некорректный или невалидный ответ LLM."""
    pass


def _build_analysis_prompt(
    scan_type: str,
    object_description: str,
    vt_summary: str,
    extra_context: Optional[str] = None,
) -> str:
    """
    Формирует промпт для анализа. Все пользовательские данные проходят через sanitize_for_llm.
    """
    obj_safe = sanitize_for_llm(object_description)
    vt_safe = sanitize_for_llm(vt_summary)
    ctx_safe = sanitize_for_llm(extra_context or "")

    prompt = f"""You are a cybersecurity analyst. You are given automated scan data and VirusTotal signals. Analyze the evidence and return a strictly structured assessment. You are an analytical layer and do not make final enforcement decisions.

Object type: {scan_type}
Scanned object: {obj_safe}
VirusTotal summary: {vt_safe}
"""
    if ctx_safe:
        prompt += f"\nAdditional context: {ctx_safe}\n"
    prompt += """
Return only valid JSON, with no markdown or extra text, in this format:
{
  "threat_type": "phishing" | "malware" | "scam" | "suspicious" | "clean",
  "risk_level": "low" | "medium" | "high",
  "explanation": "Brief, human-readable explanation in English (1–2 sentences)"
}
"""
    return prompt


def _extract_json_from_content(content: str) -> dict[str, Any]:
    """Извлекает JSON из текста ответа (обрезка markdown-блоков и т.п.)."""
    text = (content or "").strip()
    # Убираем обёртку ```json ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        text = match.group(1).strip()
    # Ищем первый { ... }
    start = text.find("{")
    if start == -1:
        raise LLMResponseError("No JSON object found in LLM response.")
    depth = 0
    end = -1
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end == -1:
        raise LLMResponseError("Malformed JSON structure in LLM response.")
    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError as e:
        raise LLMResponseError(f"Failed to parse JSON from LLM response: {e}") from e


def _validate_llm_response(data: dict[str, Any]) -> dict[str, Any]:
    """Проверяет наличие и допустимость threat_type, risk_level, explanation."""
    if not isinstance(data, dict):
        raise LLMResponseError("LLM response is not a JSON object.")
    threat = data.get("threat_type")
    if not threat or not isinstance(threat, str):
        raise LLMResponseError("LLM response is missing a valid threat_type.")
    threat_lower = threat.strip().lower()
    if threat_lower not in THREAT_TYPES:
        raise LLMResponseError(
            f"Invalid threat_type value: {threat}. Expected one of: {sorted(THREAT_TYPES)}"
        )
    risk = data.get("risk_level")
    if not risk or not isinstance(risk, str):
        raise LLMResponseError("LLM response is missing a valid risk_level.")
    risk_lower = risk.strip().lower()
    if risk_lower not in RISK_LEVELS:
        raise LLMResponseError(
            f"Invalid risk_level value: {risk}. Expected one of: {sorted(RISK_LEVELS)}"
        )
    explanation = data.get("explanation")
    if explanation is not None and not isinstance(explanation, str):
        explanation = str(explanation)
    return {
        "threat_type": threat_lower,
        "risk_level": risk_lower,
        "explanation": (explanation or "").strip(),
        "analysis_data": data,
    }


class LLMClient:
    """
    Клиент OpenRouter API для анализа угроз по данным проверки и VirusTotal.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self._api_key = (api_key or config.OPENROUTER_API_KEY).strip()
        self._model = (model or config.OPENROUTER_MODEL).strip()
        self._enabled = bool(
            self._api_key and self._model and config.is_extended_mode()
        )

    @property
    def is_enabled(self) -> bool:
        """True, если клиент может выполнять внешний LLM-анализ."""
        return self._enabled

    def analyze(
        self,
        scan_type: str,
        object_description: str,
        vt_summary: str,
        extra_context: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Отправляет данные проверки в LLM и возвращает валидированный результат:
        threat_type, risk_level, explanation, analysis_data.

        Raises:
            LLMError: при ошибке API или невалидном ответе.
        """
        if not self._enabled:
            raise LLMError(
                "LLM client is disabled: OPENROUTER_API_KEY is missing or SCAN_MODE is not EXTENDED."
            )

        prompt = _build_analysis_prompt(
            scan_type=scan_type,
            object_description=object_description,
            vt_summary=vt_summary,
            extra_context=extra_context,
        )
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 1024,
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/telegram-phishing-bot",
        }

        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT) as client:
                payload_with_json = {**payload, "response_format": {"type": "json_object"}}
                r = client.post(OPENROUTER_URL, json=payload_with_json, headers=headers)
                if r.status_code == 400 and "response_format" in (r.text or "").lower():
                    r = client.post(OPENROUTER_URL, json=payload, headers=headers)
        except httpx.TimeoutException as e:
            raise LLMError("Timed out while waiting for LLM response.") from e
        except httpx.RequestError as e:
            raise LLMError(f"LLM request failed: {e}") from e

        if r.status_code != 200:
            msg = r.text[:500] if r.text else r.reason_phrase
            if r.status_code == 429:
                raise LLMError("LLM rate limit exceeded (429).")
            if r.status_code == 401:
                raise LLMError("Invalid OpenRouter API key.")
            raise LLMError(f"LLM API returned {r.status_code}: {msg}")

        try:
            body = r.json()
        except json.JSONDecodeError as e:
            raise LLMError("LLM response is not valid JSON.") from e

        choices = body.get("choices")
        if not choices or not isinstance(choices, list):
            raise LLMResponseError("LLM response is missing choices.")
        msg = choices[0].get("message") if choices else None
        if not msg or not isinstance(msg, dict):
            raise LLMResponseError("LLM response is missing message.")
        content = msg.get("content")
        if content is None:
            content = ""
        if not isinstance(content, str):
            content = str(content)

        try:
            raw = _extract_json_from_content(content)
            return _validate_llm_response(raw)
        except LLMResponseError as e:
            logger.warning(
                "LLM response parse error: %s. Content (first 500 chars): %s",
                e,
                (content or "")[:500],
            )
            raise


def vt_summary_from_result(vt_result: dict[str, Any], object_type: str = "url") -> str:
    """
    Формирует краткую текстовую сводку из ответа VirusTotal для передачи в LLM.
    object_type: 'url' или 'file'.
    Поддерживает и полный ответ API (data.attributes.stats), и вложенный объект (attributes.stats).
    """
    if not vt_result or not isinstance(vt_result, dict):
        return "VirusTotal data is unavailable."
    data = vt_result.get("data") or vt_result
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    if not isinstance(stats, dict):
        stats = {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless = stats.get("harmless", 0)
    total = malicious + suspicious + undetected + harmless
    parts = [f"malicious: {malicious}, suspicious: {suspicious}, undetected: {undetected}, harmless: {harmless}"]
    if total:
        parts.append(f"total engines: {total}")
    return "VirusTotal stats: " + "; ".join(parts)
