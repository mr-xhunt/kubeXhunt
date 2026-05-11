"""Graphviz report renderer."""

from __future__ import annotations

from typing import Any

from kubexhunt.core.runtime import get_active_runtime
from kubexhunt.core.legacy import load_legacy_module


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def current_graph() -> list[dict[str, Any]]:
    """Return the current graph data for future Graphviz rendering."""

    return _runtime().ATTACK_GRAPH
