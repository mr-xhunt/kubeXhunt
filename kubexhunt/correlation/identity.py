"""Identity graph correlation module."""

from __future__ import annotations

import os
from typing import Any

from kubexhunt.core.legacy import load_legacy_module
from kubexhunt.core.runtime import get_active_runtime


def _runtime():
    """Return the active package runtime, falling back to legacy compatibility."""

    try:
        return get_active_runtime()
    except RuntimeError:
        return load_legacy_module()


def build_identity_graph(legacy) -> dict[str, Any]:
    """Build pod, service-account, and cloud identity links from findings and context."""

    print("[DEBUG] Building identity graph")
    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(node_id: str, node_type: str, label: str) -> None:
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "type": node_type, "label": label})

    def add_edge(source: str, target: str, relation: str) -> None:
        edges.append({"from": source, "to": target, "relation": relation})

    namespace = legacy.CTX.get("namespace", "default")
    service_account = legacy.CTX.get("sa_name", "unknown")
    pod_id = f"pod/{namespace}/compromised"
    sa_id = f"sa/{namespace}/{service_account}"
    add_node(pod_id, "pod", f"Compromised Pod ({namespace})")
    add_node(sa_id, "serviceaccount", f"SA: {service_account}")
    add_edge(pod_id, sa_id, "uses SA token" if legacy.CTX.get("token") else "running as service account")

    cloud = legacy.CTX.get("cloud", "Unknown")
    if legacy.CTX.get("aws_creds"):
        iam_id = "aws/iam-role"
        add_node(iam_id, "iam_role", "AWS IAM Role (via IMDS)")
        add_edge(sa_id, iam_id, "assumes via IMDS")
        add_node("aws/account", "aws_account", "AWS Account")
        add_edge(iam_id, "aws/account", "member of")
    elif cloud == "AWS" and os.environ.get("AWS_ROLE_ARN"):
        role_arn = os.environ.get("AWS_ROLE_ARN", "")
        iam_id = f"aws/irsa/{role_arn.split('/')[-1] or 'role'}"
        add_node(iam_id, "iam_role", f"AWS IAM Role ({role_arn or 'IRSA'})")
        add_edge(sa_id, iam_id, "bound via IRSA")
        add_node("aws/account", "aws_account", "AWS Account")
        add_edge(iam_id, "aws/account", "member of")
    elif cloud == "GKE":
        gsa_id = "gcp/service-account"
        add_node(gsa_id, "gcp_serviceaccount", "GCP Service Account (Workload Identity)")
        add_edge(sa_id, gsa_id, "bound via WI")
    elif cloud == "Azure":
        azure_id = "azure/managed-identity"
        add_node(azure_id, "azure_identity", "Azure Managed Identity")
        add_edge(sa_id, azure_id, "uses MSI")

    for finding in legacy.FINDINGS:
        check_text = finding.get("check", "").lower()
        detail = finding.get("detail", "")
        if "sa token present" in check_text or "serviceaccount" in detail.lower():
            add_node(sa_id, "serviceaccount", f"SA: {service_account}")
            if not any(edge.get("from") == pod_id and edge.get("to") == sa_id for edge in edges):
                add_edge(pod_id, sa_id, "service account context")
        if "stolen token" in finding.get("check", "").lower() and finding.get("severity") == "CRITICAL":
            for line in detail.split("\n"):
                clean = line.strip()
                if "/" in clean and "—" in clean:
                    principal = clean.split("—", 1)[0].strip()
                    parts = principal.split("/")
                    if len(parts) == 2:
                        stolen_ns, stolen_sa = parts[0][:40], parts[1][:40]
                        stolen_id = f"sa/{stolen_ns}/{stolen_sa}"
                        add_node(stolen_id, "serviceaccount", f"Stolen SA: {stolen_ns}/{stolen_sa}")
                        add_edge(pod_id, stolen_id, "token stolen via hostPath")

    for finding in legacy.FINDINGS:
        text = (finding.get("check", "") + " " + finding.get("detail", "")).lower()
        if "kubelet pki accessible" in text or "system:node" in text or "kubelet cert" in text:
            node_id = "k8s/node-identity"
            add_node(node_id, "other", "Kubernetes Node Identity")
            add_edge(pod_id, node_id, "node credential exposure")
        if "azure workload identity" in text:
            azure_id = "azure/managed-identity"
            add_node(azure_id, "azure_identity", "Azure Managed Identity")
            add_edge(sa_id, azure_id, "bound via workload identity")

    legacy.CTX["identity_graph"] = {"nodes": nodes, "edges": edges}
    print(f"[DEBUG] Identity graph built: {len(nodes)} nodes, {len(edges)} edges")
    return legacy.CTX["identity_graph"]


def build() -> dict[str, Any]:
    """Build the current identity graph using the modular implementation."""

    return build_identity_graph(_runtime())


def current() -> dict[str, Any]:
    """Return the current identity graph."""

    return _runtime().CTX.get("identity_graph", {"nodes": [], "edges": []})
