"""JSON report renderer."""

from __future__ import annotations

import json
from datetime import datetime

from kubexhunt import __version__
from kubexhunt.core.runtime import get_active_runtime
from kubexhunt.core.legacy import load_legacy_module


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def build_report(runtime) -> dict:
    """Build the JSON report payload from the current runtime."""

    return {
        "tool": "KubeXHunt",
        "version": __version__,
        "timestamp": datetime.now().isoformat(),
        "context": {
            "api": runtime.CTX.get("api"),
            "namespace": runtime.CTX.get("namespace"),
            "sa": runtime.CTX.get("sa_name"),
            "cloud": runtime.CTX.get("cloud"),
            "k8s_version": runtime.CTX.get("k8s_version", ""),
        },
        "findings": runtime.FINDINGS,
        "attack_paths": runtime.ATTACK_GRAPH,
        "token_scores": runtime.TOKEN_SCORES,
        "summary": {
            severity: len([finding for finding in runtime.FINDINGS if finding["severity"] == severity])
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
        },
    }


def save(filepath: str) -> None:
    """Write the JSON report using the modular implementation."""

    runtime = _runtime()
    with open(filepath, "w", encoding="utf-8") as handle:
        json.dump(build_report(runtime), handle, indent=2)
