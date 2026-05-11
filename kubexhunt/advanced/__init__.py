"""Advanced exploitation techniques for cloud pivoting and persistence.

Modules:
    workload_identity: Kubernetes-to-cloud identity abuse (IRSA, Workload Identity, Pod Identity)
    persistence: Persistence mechanisms (webhooks, daemonsets, CRDs, cron jobs)
"""

from kubexhunt.advanced.persistence import (
    CRDFinding,
    DaemonSetFinding,
    PersistenceChain,
    PersistenceEngine,
    WebhookFinding,
)
from kubexhunt.advanced.workload_identity import (
    AzureWIBinding,
    GCPWIBinding,
    IRSABinding,
    WorkloadIdentityAbuser,
)

__all__ = [
    "IRSABinding",
    "GCPWIBinding",
    "AzureWIBinding",
    "WorkloadIdentityAbuser",
    "PersistenceChain",
    "WebhookFinding",
    "DaemonSetFinding",
    "CRDFinding",
    "PersistenceEngine",
]
