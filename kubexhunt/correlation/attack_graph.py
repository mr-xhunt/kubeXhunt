"""Attack graph correlation module."""

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


def add_edge(source: str, target: str, relation: str, severity: str = "HIGH") -> None:
    """Delegate attack graph edge insertion to the current legacy implementation."""

    _runtime().add_attack_edge(source, target, relation, severity)


def current_graph() -> list[dict[str, Any]]:
    """Return the current live attack graph."""

    return _runtime().ATTACK_GRAPH
