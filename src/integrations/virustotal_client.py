"""
Клиент VirusTotal API v3: проверка URL и файлов с учётом rate limits и кэша в БД.
Не переходит по ссылкам и не исполняет файлы — только отправляет данные в API.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Optional, Union

import httpx

from src.config import config
from src.security.security import hash_string_for_storage

logger = logging.getLogger(__name__)

# Базовый URL VirusTotal API v3
VT_BASE = "https://www.virustotal.com/api/v3"

# Таймауты и повторные попытки
REQUEST_TIMEOUT = 60.0
POLL_INTERVAL = 15  # секунд между опросами анализа
POLL_MAX_ATTEMPTS = 24  # ~6 минут максимум ожидания
DEFAULT_RATE_LIMIT_WAIT = 60  # секунд при 429 без Retry-After


class VirusTotalError(Exception):
    """Ошибка при работе с VirusTotal API."""
    pass


class VirusTotalRateLimitError(VirusTotalError):
    """Превышен лимит запросов (429)."""
    pass


class VirusTotalClient:
    """
    Клиент VirusTotal API v3 с обработкой rate limits и опциональным кэшем в БД.
    Проверка URL через URL Scan, файлов — по хешу с последующей загрузкой при необходимости.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        cache_get: Optional[Callable[[str], Optional[dict]]] = None,
        cache_save: Optional[Callable[[int, str, str, dict], Any]] = None,
    ):
        self._api_key = (api_key or config.VIRUSTOTAL_API_KEY).strip()
        self._cache_get = cache_get
        self._cache_save = cache_save
        self._enabled = bool(self._api_key)
        self._headers = {"x-apikey": self._api_key} if self._enabled else {}

    @property
    def is_enabled(self) -> bool:
        """True, если клиент может выполнять внешние запросы к VirusTotal."""
        return self._enabled

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Выполняет HTTP-запрос с обработкой 429 и повторными попытками."""
        if not self._enabled:
            raise VirusTotalError("VirusTotal client disabled: API key is missing")
        url = path if path.startswith("http") else f"{VT_BASE}{path}"
        timeout = kwargs.pop("timeout", REQUEST_TIMEOUT)
        with httpx.Client(timeout=timeout, headers=self._headers) as client:
            response = client.request(method, url, **kwargs)
            if response.status_code == 429:
                wait = DEFAULT_RATE_LIMIT_WAIT
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = int(retry_after)
                    except ValueError:
                        pass
                logger.warning("VirusTotal rate limit (429), waiting %s seconds", wait)
                time.sleep(wait)
                return self._request(method, path, timeout=timeout, **kwargs)
            return response

    def _get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Получает результат анализа по ID."""
        r = self._request("GET", f"/analyses/{analysis_id}")
        if r.status_code != 200:
            raise VirusTotalError(
                f"VirusTotal analyses: {r.status_code} — {r.text[:500]}"
            )
        return r.json()

    def _poll_analysis_until_complete(self, analysis_id: str) -> dict[str, Any]:
        """Опрашивает анализ до завершения или таймаута."""
        for _ in range(POLL_MAX_ATTEMPTS):
            data = self._get_analysis(analysis_id)
            status = (data.get("data", {}) or {}).get("attributes", {}).get("status")
            if status == "completed":
                return data
            if status == "failed":
                raise VirusTotalError("VirusTotal analysis finished with an error.")
            time.sleep(POLL_INTERVAL)
        raise VirusTotalError("Timeout while waiting for VirusTotal analysis result.")

    def scan_url(
        self,
        url: str,
        object_hash: Optional[str] = None,
        scan_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Проверяет URL через VirusTotal URL Scan.
        Сначала проверяет кэш по object_hash; при отсутствии — отправляет URL в API,
        ждёт завершения анализа и при наличии cache_save сохраняет результат в БД.

        Returns:
            Словарь с данными VirusTotal (data.attributes.last_analysis_results и т.п.).
        """
        obj_hash = object_hash or hash_string_for_storage(url)
        if self._cache_get:
            cached = self._cache_get(obj_hash)
            if cached and cached.get("data"):
                logger.debug("VirusTotal URL: кэш по hash=%s", obj_hash[:16])
                return cached["data"]

        r = self._request("POST", "/urls", data={"url": url})
        if r.status_code not in (200, 201):
            if r.status_code == 429:
                raise VirusTotalRateLimitError("VirusTotal rate limit exceeded.")
            raise VirusTotalError(
                f"VirusTotal URL scan: {r.status_code} — {r.text[:500]}"
            )
        body = r.json()
        analysis_id = (body.get("data", {}) or {}).get("id")
        if not analysis_id:
            raise VirusTotalError("VirusTotal did not return an analysis ID.")

        result = self._poll_analysis_until_complete(analysis_id)
        if self._cache_save and scan_id is not None:
            self._cache_save(scan_id, obj_hash, "url", result)
        return result

    def get_file_report(self, file_hash: str) -> Optional[dict[str, Any]]:
        """
        Получает отчёт по файлу по SHA-256 хешу (GET /files/{id}).
        Возвращает данные файла и last_analysis_stats или None, если файл неизвестен (404).
        """
        # API ожидает id в виде base64url-encoded SHA-256; для hex передаём как есть в части документации
        # В v3 для files используется hex (см. vt-py get_object("/files/"+hash))
        r = self._request("GET", f"/files/{file_hash}")
        if r.status_code == 404:
            return None
        if r.status_code != 200:
            if r.status_code == 429:
                raise VirusTotalRateLimitError("VirusTotal rate limit exceeded.")
            raise VirusTotalError(
                f"VirusTotal file report: {r.status_code} — {r.text[:500]}"
            )
        return r.json()

    def upload_file(
        self,
        file_path: Union[str, Path],
    ) -> dict[str, Any]:
        """
        Загружает файл для сканирования (POST /files). Возвращает результат анализа
        после опроса до завершения.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "rb") as f:
            content = f.read()
        name = path.name or "file.bin"

        r = self._request(
            "POST",
            "/files",
            files={"file": (name, content)},
            headers={k: v for k, v in self._headers.items() if k.lower() != "content-type"},
        )
        if r.status_code not in (200, 201):
            if r.status_code == 429:
                raise VirusTotalRateLimitError("VirusTotal rate limit exceeded.")
            raise VirusTotalError(
                f"VirusTotal file upload: {r.status_code} — {r.text[:500]}"
            )
        body = r.json()
        analysis_id = (body.get("data", {}) or {}).get("id")
        if not analysis_id:
            raise VirusTotalError("VirusTotal did not return an analysis ID after file upload.")
        return self._poll_analysis_until_complete(analysis_id)

    def scan_file(
        self,
        file_path: Union[str, Path],
        file_hash: str,
        scan_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Проверяет файл: сначала отчёт по хешу; при отсутствии — загрузка и анализ.
        При наличии кэша возвращает закэшированный результат. Иначе сохраняет в БД через cache_save.
        """
        if self._cache_get:
            cached = self._cache_get(file_hash)
            if cached and cached.get("data"):
                logger.debug("VirusTotal file: кэш по hash=%s", file_hash[:16])
                return cached["data"]

        report = self.get_file_report(file_hash)
        if report is not None:
            # Файл уже известен VT — используем как результат (есть last_analysis_stats и т.д.)
            result = report
        else:
            result = self.upload_file(file_path)

        if self._cache_save and scan_id is not None:
            self._cache_save(scan_id, file_hash, "file", result)
        return result
