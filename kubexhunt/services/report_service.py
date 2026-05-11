"""Report service wrapper."""

from __future__ import annotations

from kubexhunt.orchestrator.pipeline import run_scan_pipeline


def run_report(args) -> int:
    """Execute report generation through the package-native pipeline."""

    return run_scan_pipeline(args)
