"""Reporter protocol."""

from typing import Protocol

from kubexhunt.core.result import ScanResult


class BaseReporter(Protocol):
    """Protocol for report renderers."""

    format_name: str

    def render(self, result: ScanResult) -> str:
        """Render a result into a string."""
