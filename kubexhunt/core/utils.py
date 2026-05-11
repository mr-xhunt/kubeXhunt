"""Shared utility helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kubexhunt.core.context import Context
from kubexhunt.core.logging import StructuredLogger, log_exception


def repo_root() -> Path:
    """Return the repository root containing the legacy script."""

    return Path(__file__).resolve().parents[2]


def safe_json_loads(
    raw: Any,
    status_code: int = 0,
    context: Context | None = None,
    logger: StructuredLogger | None = None,
) -> tuple[int, Any | None]:
    """Safely parse JSON payloads and return `(status, object)`."""

    if raw is None:
        return status_code, None
    if isinstance(raw, (dict, list)):
        return status_code, raw
    if isinstance(raw, bytes):
        raw = raw.decode(errors="replace")
    text = str(raw).strip()
    if not text:
        return status_code, None
    try:
        return status_code, json.loads(text)
    except json.JSONDecodeError as exc:
        if logger is not None:
            log_exception(logger, "Invalid JSON payload", exc, context)
        return status_code, None
