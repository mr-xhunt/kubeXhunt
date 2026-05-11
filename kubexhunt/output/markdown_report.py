"""Markdown report renderer."""

from __future__ import annotations

from datetime import datetime

from kubexhunt.core.runtime import get_active_runtime
from kubexhunt.core.legacy import load_legacy_module


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def build_report_text(runtime) -> str:
    """Build the text/markdown-style report body from the current runtime."""

    lines = [
        "KubeXHunt v1.2.0 Security Assessment Report",
        f"Generated: {datetime.now().isoformat()}",
        f"Cluster: {runtime.CTX.get('api', '')} | NS: {runtime.CTX.get('namespace', '')} | "
        f"SA: {runtime.CTX.get('sa_name', '')} | Cloud: {runtime.CTX.get('cloud', '')}",
        "",
    ]
    for finding in runtime.FINDINGS:
        lines.append(f"[{finding['severity']}] {finding['check']}")
        if finding.get("detail"):
            lines.append(f"  Detail: {finding['detail'][:300]}")
        if finding.get("remediation"):
            lines.append(f"  Fix: {finding['remediation'][:200]}")
        lines.append("")
    return "\n".join(lines)


def save(filepath: str) -> None:
    """Write the text/markdown report using the modular implementation."""

    runtime = _runtime()
    with open(filepath, "w", encoding="utf-8") as handle:
        handle.write(build_report_text(runtime))
