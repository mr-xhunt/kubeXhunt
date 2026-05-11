"""Adapters between the legacy runtime and the modular package API."""

from __future__ import annotations

from typing import Any

from kubexhunt.core.legacy import load_legacy_module


def legacy_context() -> Any:
    """Return the live legacy context object."""

    return load_legacy_module().CTX


def legacy_state() -> dict[str, Any]:
    """Return the legacy runtime state in a structured mapping."""

    legacy = load_legacy_module()
    return {
        "findings": legacy.FINDINGS,
        "attack_graph": legacy.ATTACK_GRAPH,
        "token_scores": legacy.TOKEN_SCORES,
        "current_phase": getattr(legacy, "CURRENT_PHASE", "0"),
    }
