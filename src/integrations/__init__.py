"""Модули интеграций с внешними API."""

from src.integrations.virustotal_client import (
    VirusTotalClient,
    VirusTotalError,
    VirusTotalRateLimitError,
)
from src.integrations.llm_client import (
    LLMClient,
    LLMError,
    LLMResponseError,
    vt_summary_from_result,
)
