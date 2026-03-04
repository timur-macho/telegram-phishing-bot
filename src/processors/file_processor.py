"""File scanning processor is intentionally disabled in this deployment (URL-only mode)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional


def process_file(
    file_path: Path,
    file_size: int,
    mime_type: Optional[str],
    telegram_id: int,
) -> dict[str, Any]:
    """
    File analysis is disabled.

    This function remains in the repository to keep architecture compatibility,
    but the bot does not register file handlers and will not route user traffic here.
    """
    _ = (file_path, file_size, mime_type, telegram_id)
    return {
        "success": False,
        "error_message": "File scanning is disabled. This bot currently supports URL analysis only.",
    }
