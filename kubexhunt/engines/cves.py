"""CVE engine."""

from kubexhunt.engines.base import LegacyFunctionEngine


class CVEEngine(LegacyFunctionEngine):
    """Compatibility wrapper for current CVE-focused cluster intel."""

    def __init__(self) -> None:
        super().__init__(name="cves", phase="15", function_name="phase_cluster_intel")
