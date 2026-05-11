"""Scan service preserving legacy CLI behavior."""

from __future__ import annotations

from kubexhunt.orchestrator.pipeline import run_scan_pipeline


def run_scan(args) -> int:
    """Execute the package-native scan pipeline."""

    return run_scan_pipeline(args)
