"""Attack graph data model and analysis.

This module defines the graph representation of Kubernetes attack surfaces:
- Nodes: ServiceAccounts, Pods, Nodes, Secrets, Roles, CloudIdentities, etc.
- Edges: Attack relationships (CAN_EXEC, MOUNTS, IMPERSONATES, etc.)
- Queries: Shortest-path, transitive closure, path-to-admin chains.

Designed for Phase 2+ to support structured attack path queries and chaining.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

from kubexhunt.core.models import Evidence, Severity


class NodeType(str, Enum):
    """Kubernetes and cloud identity node types."""

    # Kubernetes identity and access
    SERVICE_ACCOUNT = "ServiceAccount"
    ROLE = "Role"
    CLUSTER_ROLE = "ClusterRole"
    ROLE_BINDING = "RoleBinding"
    CLUSTER_ROLE_BINDING = "ClusterRoleBinding"

    # Kubernetes workloads
    POD = "Pod"
    DEPLOYMENT = "Deployment"
    DAEMONSET = "DaemonSet"
    STATEFULSET = "StatefulSet"
    CRONJOB = "CronJob"
    JOB = "Job"

    # Kubernetes storage
    SECRET = "Secret"
    CONFIG_MAP = "ConfigMap"

    # Kubernetes infrastructure
    NODE = "Node"
    NAMESPACE = "Namespace"

    # Kubernetes policies and extensions
    NETWORK_POLICY = "NetworkPolicy"
    POD_SECURITY_POLICY = "PodSecurityPolicy"
    POD_SECURITY_STANDARD = "PodSecurityStandard"
    VALIDATING_WEBHOOK = "ValidatingWebhook"
    MUTATING_WEBHOOK = "MutatingWebhook"
    CUSTOM_RESOURCE_DEFINITION = "CustomResourceDefinition"

    # Image and registry
    IMAGE_PULL_SECRET = "ImagePullSecret"
    CONTAINER_REGISTRY = "ContainerRegistry"

    # Cloud identities
    CLOUD_IDENTITY = "CloudIdentity"  # IRSA, Workload Identity, Pod Identity
    CLOUD_ROLE = "CloudRole"  # IAM role, service account, managed identity
    CLOUD_RESOURCE = "CloudResource"  # EC2, RDS, S3, GCS, etc.

    # Logical nodes
    CLUSTER = "Cluster"  # cluster-admin state
    NODE_ROOT = "NodeRoot"  # root shell on node


class RelationType(str, Enum):
    """Attack relationship types for Kubernetes."""

    # Execution and code path
    CAN_EXEC = "CAN_EXEC"  # pod.exec()
    CAN_EXEC_VIA_KUBELET = "CAN_EXEC_VIA_KUBELET"  # kubelet exec API
    CAN_CREATE_POD = "CAN_CREATE_POD"  # create any pod
    CAN_CREATE_EPHEMERAL = "CAN_CREATE_EPHEMERAL"  # debug containers
    CAN_PATCH_POD = "CAN_PATCH_POD"  # patch pod spec

    # RBAC
    CAN_READ = "CAN_READ"
    CAN_WRITE = "CAN_WRITE"
    CAN_DELETE = "CAN_DELETE"
    CAN_IMPERSONATE = "CAN_IMPERSONATE"  # impersonate SA/user
    CAN_ESCALATE_RBAC = "CAN_ESCALATE_RBAC"  # escalate role permissions
    CAN_MODIFY_BINDING = "CAN_MODIFY_BINDING"  # modify RoleBinding/ClusterRoleBinding

    # Identity and binding
    RUNS_AS = "RUNS_AS"  # pod runs as SA
    BOUND_TO = "BOUND_TO"  # SA/user bound to role
    INHERITS_FROM = "INHERITS_FROM"  # role aggregation inheritance

    # Mounting and access
    MOUNTS_SECRET = "MOUNTS_SECRET"
    MOUNTS_CONFIGMAP = "MOUNTS_CONFIGMAP"
    MOUNTS_HOSTPATH = "MOUNTS_HOSTPATH"
    MOUNTS_DOCKER_SOCKET = "MOUNTS_DOCKER_SOCKET"
    MOUNTS_KUBELET_SOCKET = "MOUNTS_KUBELET_SOCKET"

    # Network reachability
    CAN_REACH = "CAN_REACH"
    CAN_REACH_IMDS = "CAN_REACH_IMDS"
    CAN_REACH_API_SERVER = "CAN_REACH_API_SERVER"
    CAN_REACH_KUBELET = "CAN_REACH_KUBELET"
    CAN_REACH_ETCD = "CAN_REACH_ETCD"

    # Escape and privilege escalation
    CAN_ESCAPE_TO_NODE = "CAN_ESCAPE_TO_NODE"  # container escape via kernel CVE
    CAN_ESCAPE_TO_HOST = "CAN_ESCAPE_TO_HOST"  # via privileged + hostPath
    CAN_ESCALATE_VIA_CAPABILITIES = "CAN_ESCALATE_VIA_CAPABILITIES"

    # Cloud identity
    BOUND_TO_CLOUD_IDENTITY = "BOUND_TO_CLOUD_IDENTITY"  # IRSA, WI, Pod Identity
    CAN_ASSUME_CLOUD_ROLE = "CAN_ASSUME_CLOUD_ROLE"
    CAN_ACCESS_CLOUD_RESOURCE = "CAN_ACCESS_CLOUD_RESOURCE"  # S3, RDS, etc.

    # Admission
    BYPASSES_ADMISSION = "BYPASSES_ADMISSION"  # webhook failure policy

    # Defense evasion and persistence (Phase 3)
    BYPASSES_RUNTIME_DETECTION = "BYPASSES_RUNTIME_DETECTION"  # Falco, Tetragon, etc.
    HAS_PERSISTENCE = "HAS_PERSISTENCE"  # webhook, daemonset, crd persistence
    CAN_REACH_VIA_NETWORK = "CAN_REACH_VIA_NETWORK"  # network policy gap
    BOUND_TO_IAM_ROLE = "BOUND_TO_IAM_ROLE"  # more specific IRSA/WI binding

    # Supply chain and advanced cloud (Phase 4)
    POISONS_IMAGE = "POISONS_IMAGE"  # registry write → malicious image
    COMPROMISES_CICD = "COMPROMISES_CICD"  # pipeline secret → deploy code
    CAN_CREATE_IAM_BACKDOOR = "CAN_CREATE_IAM_BACKDOOR"  # IAM perm → backdoor
    CAN_EXTRACT_TFSTATE = "CAN_EXTRACT_TFSTATE"  # cloud storage read → creds


@dataclass
class GraphNode:
    """A node in the Kubernetes attack graph.

    Attributes:
        id: Globally unique identifier (e.g., "sa:default:default", "pod:kube-system:coredns")
        type: NodeType enum
        namespace: Kubernetes namespace (None for cluster-wide resources)
        name: Resource name
        properties: Arbitrary metadata dict
        labels: K8s labels
        annotations: K8s annotations
        can_escalate: True if this node grants privilege escalation
        is_high_priv: True if this node has elevated privileges
        is_cluster_admin: True if this node has cluster-admin access
        evidence: Supporting evidence for node attributes
    """

    id: str
    type: NodeType
    namespace: str | None = None
    name: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    can_escalate: bool = False
    is_high_priv: bool = False
    is_cluster_admin: bool = False

    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON."""
        return {
            "id": self.id,
            "type": self.type.value,
            "namespace": self.namespace,
            "name": self.name,
            "properties": self.properties,
            "labels": self.labels,
            "annotations": self.annotations,
            "can_escalate": self.can_escalate,
            "is_high_priv": self.is_high_priv,
            "is_cluster_admin": self.is_cluster_admin,
        }


@dataclass
class GraphEdge:
    """An attack relationship in the Kubernetes graph.

    Attributes:
        source_id: Source node ID
        target_id: Target node ID
        relation: RelationType enum (CAN_EXEC, MOUNTS, etc.)
        severity: Risk severity if this edge is exploited
        confidence: 0.0-1.0 probability this edge exists and is exploitable
        mitre_techniques: MITRE ATT&CK for Containers technique IDs
        evidence: Supporting evidence (findings, probes, etc.)
        is_exploitable: True if this edge represents an active attack vector
        exploit_complexity: Effort to exploit (TRIVIAL, LOW, MEDIUM, HIGH)
        exploitation_steps: Shell/kubectl commands to exploit this edge
    """

    source_id: str
    target_id: str
    relation: RelationType

    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8

    mitre_techniques: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    is_exploitable: bool = False
    exploit_complexity: Literal["TRIVIAL", "LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    exploitation_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "mitre_techniques": self.mitre_techniques,
            "is_exploitable": self.is_exploitable,
            "exploit_complexity": self.exploit_complexity,
            "exploitation_steps": self.exploitation_steps,
        }


@dataclass
class AttackGraph:
    """Complete attack graph for a Kubernetes cluster.

    Attributes:
        nodes: All reachable nodes
        edges: All attack relationships
        entry_points: Starting nodes (e.g., current pod)
    """

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        """Add or update a node."""
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a directed edge."""
        self.edges.append(edge)

    def find_shortest_path(self, source: str, target: str) -> list[str] | None:
        """Find shortest path from source to target using BFS."""
        if source not in self.nodes or target not in self.nodes:
            return None

        from collections import deque

        queue = deque([(source, [source])])
        visited = {source}

        while queue:
            current, path = queue.popleft()
            if current == target:
                return path

            for edge in self.edges:
                if edge.source_id == current and edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append((edge.target_id, path + [edge.target_id]))

        return None

    def find_paths_to_admin(self, source: str, max_hops: int = 5) -> list[list[str]]:
        """Find all paths from source to cluster-admin within max_hops."""
        paths = []

        def dfs(current: str, path: list[str], hops: int) -> None:
            if hops > max_hops:
                return

            node = self.nodes.get(current)
            if node and node.is_cluster_admin:
                paths.append(path)
                return

            for edge in self.edges:
                if edge.source_id == current and edge.target_id not in path:
                    dfs(edge.target_id, path + [edge.target_id], hops + 1)

        dfs(source, [source], 0)
        return paths

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON."""
        return {
            "nodes": {node_id: node.to_dict() for node_id, node in self.nodes.items()},
            "edges": [edge.to_dict() for edge in self.edges],
            "entry_points": self.entry_points,
        }
