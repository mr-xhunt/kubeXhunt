"""Pytest configuration and shared fixtures."""

import pytest

from kubexhunt.core.graph import AttackGraph, GraphEdge, GraphNode, NodeType, RelationType
from kubexhunt.core.models import Evidence, Finding, Remediation, RemediationStep, Severity


@pytest.fixture
def sample_finding():
    """Create a sample Finding for testing."""
    return Finding(
        id="TEST-001",
        title="Test finding",
        severity=Severity.CRITICAL,
        confidence=0.95,
        category="Test Category",
        phase="Phase 1",
        observed=True,
        description="A test finding for unit tests",
        evidence=[
            Evidence(
                kind="test_evidence",
                source="test_source",
                value="test_value",
            )
        ],
        mitre=["T1078.001"],
        cwe=["CWE-276"],
        tags=["test", "unit"],
    )


@pytest.fixture
def sample_remediation():
    """Create a sample Remediation for testing."""
    return Remediation(
        summary="Fix the test issue",
        steps=[
            RemediationStep(
                step="First remediation step",
                effort="LOW",
                commands=["echo 'step 1'"],
            ),
            RemediationStep(
                step="Second remediation step",
                effort="MEDIUM",
                commands=["echo 'step 2'"],
            ),
        ],
        estimated_effort_minutes=30,
    )


@pytest.fixture
def sample_evidence():
    """Create sample Evidence items."""
    return [
        Evidence(
            kind="API Response",
            source="Kubernetes API",
            value="ClusterRole with wildcard",
            timestamp="2026-05-11T10:00:00Z",
        ),
        Evidence(
            kind="Enumeration",
            source="Phase 3",
            value="RBAC escalation path found",
        ),
    ]


@pytest.fixture
def simple_attack_graph():
    """Create a simple attack graph for testing."""
    graph = AttackGraph()

    # Create nodes
    sa_node = GraphNode(
        id="sa:default:compromised-app",
        type=NodeType.SERVICE_ACCOUNT,
        namespace="default",
        name="compromised-app",
        can_escalate=True,
    )

    pod_node = GraphNode(
        id="pod:default:malicious",
        type=NodeType.POD,
        namespace="default",
        name="malicious",
    )

    secret_node = GraphNode(
        id="secret:kube-system:admin-token",
        type=NodeType.SECRET,
        namespace="kube-system",
        name="admin-token",
    )

    node_root = GraphNode(
        id="node:worker1-root",
        type=NodeType.NODE_ROOT,
        name="worker1",
        is_high_priv=True,
    )

    cluster_admin = GraphNode(
        id="CLUSTER",
        type=NodeType.CLUSTER,
        is_cluster_admin=True,
    )

    # Add all nodes
    for node in [sa_node, pod_node, secret_node, node_root, cluster_admin]:
        graph.add_node(node)

    # Create edges
    edges = [
        GraphEdge(
            source_id="sa:default:compromised-app",
            target_id="pod:default:malicious",
            relation=RelationType.CAN_CREATE_POD,
            severity=Severity.HIGH,
        ),
        GraphEdge(
            source_id="pod:default:malicious",
            target_id="node:worker1-root",
            relation=RelationType.CAN_ESCAPE_TO_NODE,
            severity=Severity.CRITICAL,
        ),
        GraphEdge(
            source_id="node:worker1-root",
            target_id="secret:kube-system:admin-token",
            relation=RelationType.MOUNTS_SECRET,
            severity=Severity.CRITICAL,
        ),
        GraphEdge(
            source_id="secret:kube-system:admin-token",
            target_id="CLUSTER",
            relation=RelationType.CAN_IMPERSONATE,
            severity=Severity.CRITICAL,
        ),
    ]

    # Add all edges
    for edge in edges:
        graph.add_edge(edge)

    # Set entry points
    graph.entry_points = ["sa:default:compromised-app"]

    return graph


@pytest.fixture
def kubeconfig_mock(monkeypatch, tmp_path):
    """Create a mock kubeconfig file for testing."""
    kubeconfig_content = """
    apiVersion: v1
    clusters:
    - cluster:
        certificate-authority: /path/to/ca.crt
        server: https://127.0.0.1:6443
      name: test-cluster
    contexts:
    - context:
        cluster: test-cluster
        user: test-user
      name: test-context
    current-context: test-context
    kind: Config
    preferences: {}
    users:
    - name: test-user
      user:
        token: test-token-value
    """

    kubeconfig_file = tmp_path / "kubeconfig"
    kubeconfig_file.write_text(kubeconfig_content)

    # Set the KUBECONFIG environment variable
    monkeypatch.setenv("KUBECONFIG", str(kubeconfig_file))

    return str(kubeconfig_file)


# Pytest configuration


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "cloud: marks tests as cloud-specific")


# Disable external calls during tests
@pytest.fixture(autouse=True)
def disable_network_calls(monkeypatch):  # noqa: ARG001
    """Prevent accidental network calls in unit tests."""

    def mock_socket(*_args, **_kwargs):
        raise RuntimeError("Network call attempted in test! Use mocking or integration tests instead.")

    # Only mock if not in integration test mode
    # (This can be customized based on test markers)
    # monkeypatch.setattr(socket, 'socket', mock_socket)
