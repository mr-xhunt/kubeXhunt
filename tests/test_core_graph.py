"""Tests for attack graph data structures and analysis."""

import pytest

from kubexhunt.core.graph import (
    AttackGraph,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
)
from kubexhunt.core.models import Evidence, Severity


class TestGraphNode:
    """Test GraphNode creation and properties."""

    def test_create_sa_node(self):
        """Test creating a ServiceAccount node."""
        node = GraphNode(
            id="sa:default:app",
            type=NodeType.SERVICE_ACCOUNT,
            namespace="default",
            name="app",
        )

        assert node.id == "sa:default:app"
        assert node.type == NodeType.SERVICE_ACCOUNT
        assert node.namespace == "default"

    def test_create_pod_node(self):
        """Test creating a Pod node."""
        node = GraphNode(
            id="pod:default:nginx",
            type=NodeType.POD,
            namespace="default",
            name="nginx",
            labels={"app": "web"},
            annotations={"description": "web server"},
        )

        assert node.type == NodeType.POD
        assert node.labels["app"] == "web"

    def test_create_cluster_node(self):
        """Test creating a cluster (cluster-admin) node."""
        node = GraphNode(
            id="CLUSTER",
            type=NodeType.CLUSTER,
            is_cluster_admin=True,
        )

        assert node.type == NodeType.CLUSTER
        assert node.is_cluster_admin is True

    def test_node_with_evidence(self):
        """Test node with evidence."""
        node = GraphNode(
            id="sa:default:app",
            type=NodeType.SERVICE_ACCOUNT,
            evidence=[
                Evidence(kind="SA.rules", source="RBAC", value="can create pods"),
            ],
        )

        assert len(node.evidence) == 1

    def test_node_to_dict(self):
        """Test serializing node to dict."""
        node = GraphNode(
            id="sa:default:app",
            type=NodeType.SERVICE_ACCOUNT,
            is_high_priv=True,
        )

        node_dict = node.to_dict()

        assert node_dict["id"] == "sa:default:app"
        assert node_dict["type"] == "ServiceAccount"
        assert node_dict["is_high_priv"] is True


class TestGraphEdge:
    """Test GraphEdge creation and properties."""

    def test_create_can_exec_edge(self):
        """Test creating a CAN_EXEC edge."""
        edge = GraphEdge(
            source_id="sa:default:app",
            target_id="pod:default:nginx",
            relation=RelationType.CAN_EXEC,
            severity=Severity.CRITICAL,
            confidence=0.95,
        )

        assert edge.source_id == "sa:default:app"
        assert edge.target_id == "pod:default:nginx"
        assert edge.relation == RelationType.CAN_EXEC
        assert edge.severity == Severity.CRITICAL

    def test_create_mounts_secret_edge(self):
        """Test creating a MOUNTS_SECRET edge."""
        edge = GraphEdge(
            source_id="pod:default:app",
            target_id="secret:default:api-key",
            relation=RelationType.MOUNTS_SECRET,
            severity=Severity.HIGH,
            confidence=1.0,
        )

        assert edge.relation == RelationType.MOUNTS_SECRET

    def test_edge_with_mitre_techniques(self):
        """Test edge with MITRE ATT&CK mapping."""
        edge = GraphEdge(
            source_id="sa:default:app",
            target_id="CLUSTER",
            relation=RelationType.CAN_IMPERSONATE,
            mitre_techniques=["T1078.001", "T1087.002"],
        )

        assert len(edge.mitre_techniques) == 2

    def test_edge_to_dict(self):
        """Test serializing edge to dict."""
        edge = GraphEdge(
            source_id="sa:default:app",
            target_id="pod:default:nginx",
            relation=RelationType.CAN_EXEC,
            severity=Severity.CRITICAL,
            is_exploitable=True,
        )

        edge_dict = edge.to_dict()

        assert edge_dict["source_id"] == "sa:default:app"
        assert edge_dict["relation"] == "CAN_EXEC"
        assert edge_dict["severity"] == "CRITICAL"
        assert edge_dict["is_exploitable"] is True


class TestAttackGraph:
    """Test AttackGraph construction and queries."""

    @pytest.fixture
    def simple_graph(self):
        """Create a simple attack graph."""
        graph = AttackGraph()

        # Add nodes
        sa_node = GraphNode(
            id="sa:default:app",
            type=NodeType.SERVICE_ACCOUNT,
            can_escalate=True,
        )
        pod_node = GraphNode(
            id="pod:default:nginx",
            type=NodeType.POD,
        )
        admin_node = GraphNode(
            id="CLUSTER",
            type=NodeType.CLUSTER,
            is_cluster_admin=True,
        )

        graph.add_node(sa_node)
        graph.add_node(pod_node)
        graph.add_node(admin_node)

        # Add edges
        graph.add_edge(
            GraphEdge(
                source_id="sa:default:app",
                target_id="pod:default:nginx",
                relation=RelationType.CAN_EXEC,
            )
        )
        graph.add_edge(
            GraphEdge(
                source_id="pod:default:nginx",
                target_id="CLUSTER",
                relation=RelationType.CAN_ESCAPE_TO_NODE,
            )
        )

        return graph

    def test_add_node(self):
        """Test adding a node to graph."""
        graph = AttackGraph()
        node = GraphNode(id="sa:default:app", type=NodeType.SERVICE_ACCOUNT)

        graph.add_node(node)

        assert "sa:default:app" in graph.nodes

    def test_add_edge(self):
        """Test adding an edge to graph."""
        graph = AttackGraph()
        edge = GraphEdge(
            source_id="sa:default:app",
            target_id="pod:default:nginx",
            relation=RelationType.CAN_EXEC,
        )

        graph.add_edge(edge)

        assert len(graph.edges) == 1

    def test_shortest_path_simple(self, simple_graph):
        """Test finding shortest path in simple graph."""
        path = simple_graph.find_shortest_path("sa:default:app", "CLUSTER")

        assert path is not None
        assert path[0] == "sa:default:app"
        assert path[-1] == "CLUSTER"
        assert len(path) == 3  # sa -> pod -> cluster

    def test_shortest_path_nonexistent(self, simple_graph):
        """Test shortest path when none exists."""
        simple_graph.add_node(GraphNode(id="isolated", type=NodeType.POD))

        path = simple_graph.find_shortest_path("sa:default:app", "isolated")

        assert path is None

    def test_shortest_path_invalid_nodes(self, simple_graph):
        """Test shortest path with invalid node IDs."""
        path = simple_graph.find_shortest_path("nonexistent1", "nonexistent2")

        assert path is None

    def test_find_paths_to_admin(self, simple_graph):
        """Test finding all paths to cluster-admin."""
        paths = simple_graph.find_paths_to_admin("sa:default:app")

        assert len(paths) > 0
        assert paths[0][-1] == "CLUSTER"

    def test_find_paths_to_admin_no_path(self, simple_graph):
        """Test finding paths when none exist."""
        simple_graph.add_node(GraphNode(id="isolated", type=NodeType.POD))

        paths = simple_graph.find_paths_to_admin("isolated")

        assert len(paths) == 0

    def test_graph_to_dict(self, simple_graph):
        """Test serializing entire graph to dict."""
        graph_dict = simple_graph.to_dict()

        assert "nodes" in graph_dict
        assert "edges" in graph_dict
        assert len(graph_dict["nodes"]) == 3
        assert len(graph_dict["edges"]) == 2

    def test_entry_points(self):
        """Test setting and using entry points."""
        graph = AttackGraph(entry_points=["sa:default:app"])

        assert "sa:default:app" in graph.entry_points


class TestGraphEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_graph(self):
        """Test operations on empty graph."""
        graph = AttackGraph()

        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_self_loop(self):
        """Test edge from node to itself."""
        graph = AttackGraph()
        node = GraphNode(id="sa:default:app", type=NodeType.SERVICE_ACCOUNT)
        graph.add_node(node)

        edge = GraphEdge(
            source_id="sa:default:app",
            target_id="sa:default:app",
            relation=RelationType.CAN_ESCALATE_RBAC,
        )
        graph.add_edge(edge)

        path = graph.find_shortest_path("sa:default:app", "sa:default:app")

        assert path == ["sa:default:app"]

    def test_circular_path(self):
        """Test handling of circular paths."""
        graph = AttackGraph()

        # Create a cycle: A -> B -> C -> A
        for node_id in ["A", "B", "C"]:
            graph.add_node(GraphNode(id=node_id, type=NodeType.POD))

        graph.add_edge(GraphEdge(source_id="A", target_id="B", relation=RelationType.CAN_EXEC))
        graph.add_edge(GraphEdge(source_id="B", target_id="C", relation=RelationType.CAN_EXEC))
        graph.add_edge(GraphEdge(source_id="C", target_id="A", relation=RelationType.CAN_EXEC))

        # BFS should still find shortest path without infinite loop
        path = graph.find_shortest_path("A", "C")

        assert path == ["A", "B", "C"]

    @pytest.mark.parametrize(
        "node_type",
        [
            NodeType.SERVICE_ACCOUNT,
            NodeType.POD,
            NodeType.NODE,
            NodeType.SECRET,
            NodeType.CLUSTER,
        ],
    )
    def test_various_node_types(self, node_type):
        """Test creating nodes of various types."""
        node = GraphNode(id=f"test-{node_type.value}", type=node_type)

        assert node.type == node_type
        assert node.type.value in [nt.value for nt in NodeType]

    @pytest.mark.parametrize(
        "relation_type",
        [
            RelationType.CAN_EXEC,
            RelationType.CAN_CREATE_POD,
            RelationType.MOUNTS_SECRET,
            RelationType.CAN_ESCALATE_RBAC,
            RelationType.CAN_REACH_IMDS,
        ],
    )
    def test_various_relation_types(self, relation_type):
        """Test creating edges with various relation types."""
        edge = GraphEdge(
            source_id="A",
            target_id="B",
            relation=relation_type,
        )

        assert edge.relation == relation_type
        assert edge.relation.value in [rt.value for rt in RelationType]
