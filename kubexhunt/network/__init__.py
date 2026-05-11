"""Network policy analysis and lateral movement detection.

Analyze Kubernetes network policies, identify connectivity gaps, and generate
lateral movement commands for pod-to-pod pivoting.

Modules:
    policy_analyzer: CNI analysis and network policy gap detection
"""

from kubexhunt.network.policy_analyzer import (
    CNIPlugin,
    ConnectivityMatrix,
    NetworkPath,
    NetworkPolicyAnalyzer,
    PolicyGap,
)

__all__ = [
    "CNIPlugin",
    "PolicyGap",
    "ConnectivityMatrix",
    "NetworkPath",
    "NetworkPolicyAnalyzer",
]
