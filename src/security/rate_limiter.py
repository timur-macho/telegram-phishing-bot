"""
Rate limiting по пользователю: in-memory хранилище, проверка лимитов,
понятные сообщения при превышении.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Optional

from src.config import config


class RateLimiter:
    """
    Ограничение числа запросов на пользователя в скользящем окне (секунды).
    Хранилище — in-memory (подходит для одного инстанса бота).
    Для нескольких воркеров нужен Redis (расширение позже).
    """

    def __init__(
        self,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ):
        self.max_requests = max_requests if max_requests is not None else config.RATE_LIMIT_PER_USER
        self.window_seconds = window_seconds if window_seconds is not None else config.RATE_LIMIT_WINDOW
        # user_id -> список меток времени запросов в окне
        self._requests: dict[int, list[float]] = defaultdict(list)

    def _clean_old(self, user_id: int, now: float) -> None:
        """Удаляет метки старше окна для пользователя."""
        cutoff = now - self.window_seconds
        self._requests[user_id] = [t for t in self._requests[user_id] if t > cutoff]

    def is_allowed(self, user_id: int) -> tuple[bool, Optional[str]]:
        """
        Проверяет, разрешён ли ещё один запрос для пользователя.
        Returns:
            (True, None) — можно выполнить запрос;
            (False, message) — лимит превышен, message — текст для пользователя.
        """
        now = time.monotonic()
        self._clean_old(user_id, now)
        times = self._requests[user_id]
        if len(times) >= self.max_requests:
            # Время до освобождения первого слота в окне
            oldest = min(times)
            wait_sec = max(0, self.window_seconds - (now - oldest))
            if wait_sec <= 0:
                # уже можно — слот освободился
                self._clean_old(user_id, now)
                times = self._requests[user_id]
            else:
                mins = int(wait_sec // 60)
                secs = int(wait_sec % 60)
                if mins > 0:
                    msg = f"Слишком много запросов. Попробуйте через {mins} мин."
                else:
                    msg = f"Слишком много запросов. Подождите {secs} сек."
                return False, msg
        return True, None

    def record_request(self, user_id: int) -> None:
        """Фиксирует один запрос пользователя (вызывать после is_allowed == True)."""
        now = time.monotonic()
        self._clean_old(user_id, now)
        self._requests[user_id].append(now)

    def remaining(self, user_id: int) -> int:
        """Сколько запросов ещё доступно в текущем окне."""
        now = time.monotonic()
        self._clean_old(user_id, now)
        return max(0, self.max_requests - len(self._requests[user_id]))


# Глобальный экземпляр для использования в боте
rate_limiter = RateLimiter()
