"""Scoring helpers."""

from __future__ import annotations

from typing import Any

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.core.runtime import get_active_runtime


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def score_token(token: str, label: str = "current") -> dict[str, Any]:
    """Delegate privilege scoring to the legacy implementation."""

    return _runtime().score_token(token, label)
