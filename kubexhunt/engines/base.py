"""Base engine protocol and runtime resolution helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from kubexhunt.api.base import KubeApiClient
from kubexhunt.core.config import ScanConfig
from kubexhunt.core.context import Context
from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.core.models import Finding
from kubexhunt.core.runtime import get_active_runtime
from kubexhunt.core.state import ScanState


class BaseEngine(Protocol):
    """Protocol for all scanning engines."""

    name: str
    phase: str

    async def run(
        self,
        context: Context,
        config: ScanConfig,
        state: ScanState,
        api_client: KubeApiClient,
    ) -> list[Finding]:
        """Run the engine and return normalized findings."""


@dataclass
class LegacyFunctionEngine:
    """Compatibility engine that delegates to a legacy phase function."""

    name: str
    phase: str
    function_name: str

    async def run(
        self,
        _context: Context,
        _config: ScanConfig,
        _state: ScanState,
        _api_client: KubeApiClient,
    ) -> list[Finding]:
        """Execute the mapped legacy function unchanged."""

        legacy = load_legacy_module()
        before = len(legacy.FINDINGS)
        getattr(legacy, self.function_name)()
        return legacy.FINDINGS[before:]


def resolve_runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()
