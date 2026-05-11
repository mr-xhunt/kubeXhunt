"""Operational security (opsec) rating system for KubeXHunt phases and checks.

Each phase/check is rated on detectability by audit logs, monitoring agents, and network IDS.
This helps operators understand the risk-reward of running specific checks.

Ratings:
- SILENT: Indistinguishable from normal pod behavior
- QUIET: Hard to detect; requires log analysis or specific monitoring
- MEDIUM: Detectable with standard audit logging or behavioral monitoring
- LOUD: Immediate detection; creates obvious anomalies in logs
"""

from enum import Enum
from typing import Literal

OpsecRating = Literal["SILENT", "QUIET", "MEDIUM", "LOUD"]


class OpSecLevel(str, Enum):
    """Opsec rating scale."""

    SILENT = "SILENT"  # ⚪ Indistinguishable from normal behavior
    QUIET = "QUIET"  # 🟢 Hard to detect; requires dedicated monitoring
    MEDIUM = "MEDIUM"  # 🟡 Detectable with standard audit logs
    LOUD = "LOUD"  # 🔴 Obvious anomalies; immediate detection


PHASE_OPSEC_RATINGS: dict[int, OpsecRating] = {
    # Phase 0: Setup (read local files, install kubectl)
    0: "QUIET",
    # Phase 1: Pod reconnaissance (read mounts, env, own token)
    1: "SILENT",
    # Phase 2: Cloud metadata (IMDS requests)
    2: "QUIET",  # Normal for cloud-aware workloads, but repeated 169.254.x.x requests can be suspicious
    # Phase 3: RBAC analysis (API server queries)
    3: "MEDIUM",  # GET /api/v1/... is logged; looks like debugging
    # Phase 4: Network scanning (TCP connections, DNS brute)
    4: "LOUD",  # Port scanning creates obvious connection patterns
    # Phase 5: Container escape (kernel exploit attempts)
    5: "LOUD",  # CVE exploitation, /proc manipulation, seccomp violations
    # Phase 6: Pod persistence (admission webhook analysis)
    6: "MEDIUM",  # GET webhook configurations is auditable
    # Phase 7: Kubelet enumeration (10250, 10255 access)
    7: "MEDIUM",  # Accessing kubelet API is unusual but not necessarily noisy
    # Phase 8: Privilege escalation (create pods, modify RBAC)
    8: "LOUD",  # Pod creation and RBAC changes are heavily logged and monitored
    # Phase 9: Supply chain (registry probe, image pull)
    9: "MEDIUM",  # Image pulls are normal, but unauthorized registries are suspicious
    # Phase 10-12: Cloud platforms (EKS, GKE, Azure)
    10: "QUIET",  # EKS enumeration via API
    11: "QUIET",  # GKE enumeration via API
    12: "QUIET",  # Azure enumeration via API
    # Phase 13: Secrets enumeration (kubectl get secrets -A)
    13: "LOUD",  # Bulk secret retrieval is a major red flag
    # Phase 14: DoS and resource exhaustion
    14: "LOUD",  # Resource spikes are immediately visible
    # Phase 15: Cluster intelligence (node enumeration, API endpoint probing)
    15: "MEDIUM",  # API queries are logged; external endpoint probes may be suspicious
    # Phases 16+: Advanced/platform-specific
    16: "MEDIUM",
    17: "MEDIUM",
    18: "MEDIUM",
    19: "MEDIUM",
    20: "MEDIUM",
    21: "MEDIUM",
    22: "MEDIUM",
    23: "MEDIUM",
    24: "MEDIUM",
    25: "MEDIUM",
    26: "MEDIUM",
}

# Per-API-verb opsec ratings
VERB_OPSEC_RATINGS: dict[str, OpsecRating] = {
    # Silent operations
    "get": "QUIET",  # Single resource fetch, normal debugging
    "watch": "QUIET",  # Normal workload observation
    # Quiet operations
    "list": "MEDIUM",  # Bulk listing is less suspicious than -A, but still unusual from a pod
    "list-all": "LOUD",  # kubectl get secrets -A is a clear signal
    # Medium operations
    "create": "LOUD",  # Pod/role creation is heavily monitored
    "patch": "MEDIUM",  # Could be normal config update, but unusual from unprivileged pod
    "update": "MEDIUM",  # Similar to patch
    "delete": "LOUD",  # Deletion is heavily logged
    # Loud operations
    "exec": "LOUD",  # Interactive exec is obvious in audit logs
    "logs": "QUIET",  # Log reading is normal
    "port-forward": "MEDIUM",  # Port forwarding is suspicious from a pod
    "impersonate": "LOUD",  # Impersonation is a clear attack signal
    "escalate": "LOUD",  # Role escalation is immediately flagged
    "bind": "LOUD",  # RBAC binding changes are critical logs
}

# Per-resource opsec ratings
RESOURCE_OPSEC_RATINGS: dict[str, OpsecRating] = {
    # Silent
    "pods": "QUIET",
    "pods/log": "QUIET",
    "services": "QUIET",
    "endpoints": "QUIET",
    "configmaps": "QUIET",
    # Quiet
    "nodes": "QUIET",  # Node enumeration is normal for cluster awareness
    "namespaces": "QUIET",
    # Medium
    "rolebindings": "MEDIUM",
    "clusterrolebindings": "MEDIUM",
    "roles": "MEDIUM",
    "clusterroles": "MEDIUM",
    "serviceaccounts": "MEDIUM",
    # Loud
    "secrets": "LOUD",  # Secret access is heavily audited
    "secrets/token": "LOUD",
    # Network
    "networkpolicies": "MEDIUM",
}


def get_api_call_opsec_rating(verb: str, resource: str, namespace: str | None = None) -> OpsecRating:
    """Estimate opsec impact of an API call.

    Args:
        verb: Kubernetes API verb (get, list, create, etc.)
        resource: Resource type (pods, secrets, rolebindings, etc.)
        namespace: If None, assumes cluster-wide operation (louder)

    Returns:
        OpsecRating: SILENT, QUIET, MEDIUM, or LOUD
    """
    verb_rating = VERB_OPSEC_RATINGS.get(verb.lower(), "MEDIUM")
    resource_rating = RESOURCE_OPSEC_RATINGS.get(resource.lower(), "MEDIUM")

    # Cluster-wide (-A) operations are louder
    if namespace is None and verb.lower() == "list":
        return "LOUD"

    # Combine ratings: worst (loudest) wins
    order = {"SILENT": 0, "QUIET": 1, "MEDIUM": 2, "LOUD": 3}
    combined = max(order.get(verb_rating, 2), order.get(resource_rating, 2))
    for rating_name, rating_value in order.items():
        if rating_value == combined:
            return rating_name  # type: ignore

    return "MEDIUM"


def get_phase_opsec_rating(phase_num: int) -> OpsecRating:
    """Get opsec rating for a specific phase.

    Args:
        phase_num: Phase number (0-26+)

    Returns:
        OpsecRating: Estimated detectability
    """
    return PHASE_OPSEC_RATINGS.get(phase_num, "MEDIUM")


def should_skip_phase_in_stealth_mode(phase_num: int, stealth_level: int) -> bool:
    """Determine if a phase should be skipped based on stealth level.

    Args:
        phase_num: Phase number
        stealth_level: 0 (off), 1 (jitter+UA), 2 (full evasion)

    Returns:
        True if phase should be skipped
    """
    if stealth_level == 0:
        return False  # No stealth, run all

    phase_rating = get_phase_opsec_rating(phase_num)

    if stealth_level == 1:
        # Skip only LOUD phases
        return phase_rating == "LOUD"

    if stealth_level == 2:
        # Skip LOUD and MEDIUM phases
        return phase_rating in ("LOUD", "MEDIUM")

    return False
