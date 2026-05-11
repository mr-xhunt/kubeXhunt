"""Configuration models for KubeXHunt."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan-time configuration."""

    fast: bool = False
    full: bool = False
    mutate: bool = False
    plan_only: bool = True
    concurrency: int = 8
    timeout_seconds: int = 8
    retries: int = 2
    output_format: str = "json"
    output_path: str | None = None
    fail_on: str | None = None
