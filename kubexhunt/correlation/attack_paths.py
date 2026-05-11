"""Attack path correlation module."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.core.runtime import get_active_runtime


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def synthesise_attack_graph(legacy) -> None:
    """Build attack graph edges from findings when no live graph exists."""

    namespace = legacy.CTX.get("namespace", "default")
    service_account = legacy.CTX.get("sa_name", "unknown")
    pod = f"Compromised Pod ({namespace}/{service_account})"

    has_imds = False
    has_secret = False
    has_privileged = False
    has_rbac_escalation = False
    has_etcd = False
    has_node_escape = False
    has_stolen_token = False
    has_webhook = False

    for finding in legacy.FINDINGS:
        if finding.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        text = (finding.get("check", "") + " " + finding.get("detail", "")).lower()
        if any(keyword in text for keyword in ("imds", "169.254", "aws cred", "gke", "azure")):
            has_imds = True
        if any(keyword in text for keyword in ("secret", "token", "credential", "kubeconfig")):
            has_secret = True
        if any(
            keyword in text for keyword in ("privileged", "host path", "hostpath", "hostipc", "hostpid", "hostnetwork")
        ):
            has_privileged = True
        if any(
            keyword in text for keyword in ("clusterrole", "wildcard", "rbac escalat", "cluster-admin", "cluster admin")
        ):
            has_rbac_escalation = True
        if "etcd" in text:
            has_etcd = True
        if any(keyword in text for keyword in ("escape", "breakout", "cve-2022-0847", "dirtypipe", "runc")):
            has_node_escape = True
        if any(keyword in text for keyword in ("stolen token", "steal", "/var/lib/kubelet")):
            has_stolen_token = True
        if any(keyword in text for keyword in ("webhook", "admission", "failurepolicy=ignore")):
            has_webhook = True

    if has_imds:
        legacy.add_attack_edge(pod, "Cloud IMDS Endpoint", "HTTP GET 169.254.169.254", "CRITICAL")
        legacy.add_attack_edge("Cloud IMDS Endpoint", "IAM Role Credentials", "Retrieve temp credentials", "CRITICAL")
        legacy.add_attack_edge(
            "IAM Role Credentials", "Cloud Account Compromise", "aws/gcloud/az CLI lateral movement", "CRITICAL"
        )

    if has_secret:
        legacy.add_attack_edge(pod, "K8s API Server", "SA token auth", "HIGH")
        legacy.add_attack_edge("K8s API Server", "kube-system Secrets", "kubectl get secrets -A", "HIGH")

    if has_rbac_escalation:
        legacy.add_attack_edge("kube-system Secrets", "Cluster Admin Token", "Extract high-priv SA token", "CRITICAL")
        legacy.add_attack_edge(
            "Cluster Admin Token", "Full Cluster Control", "kubectl create clusterrolebinding", "CRITICAL"
        )

    if has_privileged:
        legacy.add_attack_edge(pod, "Node Filesystem", "hostPath:/ mount or privileged container", "CRITICAL")
        legacy.add_attack_edge("Node Filesystem", "Node Root Shell", "chroot /host or nsenter -t 1", "CRITICAL")

    if has_node_escape or has_stolen_token:
        legacy.add_attack_edge(
            "Node Root Shell", "All SA Tokens on Node", "find /var/lib/kubelet/pods -name token", "CRITICAL"
        )
        legacy.add_attack_edge(
            "All SA Tokens on Node", "Full Cluster Control", "Score tokens, use highest-priv", "CRITICAL"
        )

    if has_etcd:
        legacy.add_attack_edge(pod, "etcd (port 2379)", "Direct TCP — no TLS/auth", "HIGH")
        legacy.add_attack_edge(
            "etcd (port 2379)",
            "All K8s Secrets (plaintext)",
            "ETCDCTL_API=3 etcdctl get /registry/secrets/ --prefix",
            "CRITICAL",
        )
        legacy.add_attack_edge(
            "All K8s Secrets (plaintext)", "Full Cluster Control", "Extract cluster-admin token from etcd", "CRITICAL"
        )

    if has_webhook:
        legacy.add_attack_edge(pod, "Admission Webhook Bypass", "failurePolicy=Ignore + webhook unreachable", "HIGH")
        legacy.add_attack_edge(
            "Admission Webhook Bypass", "Unconstrained Pod Creation", "PSP/Kyverno/OPA policies skipped", "CRITICAL"
        )
        legacy.add_attack_edge(
            "Unconstrained Pod Creation", "Node Root Shell", "Create privileged pod with hostPath:/", "CRITICAL"
        )

    if legacy.CTX.get("token") and not any(edge["from"] == pod and "API" in edge["to"] for edge in legacy.ATTACK_GRAPH):
        legacy.add_attack_edge(pod, "K8s API Server", "Mounted SA token", "HIGH")

    print(f"[DEBUG] Synthesised {len(legacy.ATTACK_GRAPH)} attack graph edges from findings")


def optimize_attack_paths(legacy) -> list[dict[str, Any]]:
    """Compute all valid attack paths from the directed attack graph."""

    print("[DEBUG] Optimizing attack paths")

    if not legacy.STATE.attack_graph:
        print("[DEBUG] ATTACK_GRAPH empty — synthesising edges from FINDINGS")
        synthesise_attack_graph(legacy)

    if not legacy.STATE.attack_graph:
        legacy.STATE.optimal_paths = []
        legacy.CTX["optimal_paths"] = []
        print("[DEBUG] No edges after synthesis — optimal paths empty")
        return []

    severity_score = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}

    adjacency: dict = defaultdict(list)
    indegree: dict[str, int] = defaultdict(int)
    nodes = set()
    for edge in legacy.STATE.attack_graph:
        adjacency[edge["from"]].append(edge)
        indegree[edge["to"]] += 1
        nodes.add(edge["from"])
        nodes.add(edge["to"])

    starts = [node for node in nodes if indegree[node] == 0] or [edge["from"] for edge in legacy.STATE.attack_graph]
    seen_paths = set()
    all_paths = []

    def severity_for(edges: list[dict[str, Any]]) -> str:
        severities = [edge.get("severity", "LOW") for edge in edges]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        return "LOW"

    def record_path(path_nodes: list[str], path_edges: list[dict[str, Any]]) -> None:
        key = tuple(path_nodes)
        if key in seen_paths or not path_edges:
            return
        seen_paths.add(key)
        risk_score = sum(severity_score.get(edge.get("severity", "LOW"), 0) for edge in path_edges)
        all_paths.append(
            {
                "path": list(path_nodes),
                "edges": list(path_edges),
                "risk_score": risk_score,
                "steps": len(path_edges),
                "severity": severity_for(path_edges),
            }
        )

    def dfs(node: str, path_nodes: list[str], path_edges: list[dict[str, Any]]) -> None:
        next_edges = [edge for edge in adjacency.get(node, []) if edge["to"] not in path_nodes]
        if path_edges:
            record_path(path_nodes, path_edges)
        if not next_edges:
            return
        for edge in next_edges:
            dfs(edge["to"], path_nodes + [edge["to"]], path_edges + [edge])

    for start in starts:
        dfs(start, [start], [])

    all_paths.sort(key=lambda path: (path["risk_score"], path["steps"]), reverse=True)
    legacy.STATE.optimal_paths = all_paths[:10]
    legacy.CTX["optimal_paths"] = legacy.STATE.optimal_paths
    print(
        f"[DEBUG] Optimal attack paths computed: {len(all_paths)} total, top {len(legacy.STATE.optimal_paths)} stored"
    )
    return legacy.STATE.optimal_paths


def optimize() -> list[dict[str, Any]]:
    """Run the current attack path optimizer."""

    return optimize_attack_paths(_runtime())


def current_paths() -> list[dict[str, Any]]:
    """Return the current optimized attack paths."""

    return _runtime().CTX.get("optimal_paths", [])
