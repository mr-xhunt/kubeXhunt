"""Plugin protocol."""

from typing import Protocol

from kubexhunt.api.base import KubeApiClient
from kubexhunt.core.config import ScanConfig
from kubexhunt.core.context import Context
from kubexhunt.core.models import Finding
from kubexhunt.core.state import ScanState


class BasePlugin(Protocol):
    """Protocol for plugins."""

    name: str
    version: str

    async def run(
        self,
        context: Context,
        config: ScanConfig,
        state: ScanState,
        api_client: KubeApiClient,
    ) -> list[Finding]:
        """Run the plugin."""
