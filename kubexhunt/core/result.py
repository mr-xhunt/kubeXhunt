"""Final normalized scan result."""

from dataclasses import dataclass

from kubexhunt.core.config import ScanConfig
from kubexhunt.core.context import Context
from kubexhunt.core.state import ScanState


@dataclass
class ScanResult:
    """Normalized container for final scan output."""

    context: Context
    config: ScanConfig
    state: ScanState
    summary: dict
