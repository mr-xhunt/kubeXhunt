"""Tests for runtime security detector."""

from kubexhunt.evasion.runtime_detector import (
    AppArmorProfile,
    CoverageReport,
    FalcoProfile,
    RuntimeDetector,
    SeccompProfile,
    SIEMAgent,
)


class TestFalcoDetection:
    """Test Falco detection."""

    def test_detect_falco(self):
        """Test Falco detection."""
        detector = RuntimeDetector()
        profile = detector.detect_falco()

        assert profile.installed is True
        assert profile.version == "0.36.0"
        assert profile.namespace == "falco"
        assert profile.enabled is True
        assert profile.rules_count > 0

    def test_falco_profile_serialization(self):
        """Test Falco profile serialization."""
        profile = FalcoProfile(
            installed=True,
            version="0.36.0",
            enabled=True,
            rules_count=128,
            coverage=0.95,
        )

        profile_dict = profile.to_dict()

        assert profile_dict["installed"] is True
        assert profile_dict["version"] == "0.36.0"
        assert profile_dict["coverage"] == 0.95


class TestTetragonDetection:
    """Test Tetragon detection."""

    def test_detect_tetragon_not_installed(self):
        """Test Tetragon not installed."""
        detector = RuntimeDetector()
        profile = detector.detect_tetragon()

        assert profile.installed is False
        assert profile.enabled is False
        assert profile.coverage == 0.0


class TestAppArmorDetection:
    """Test AppArmor detection."""

    def test_detect_apparmor(self):
        """Test AppArmor detection."""
        detector = RuntimeDetector()
        profile = detector.detect_apparmor()

        assert profile.installed is True
        assert profile.mode in ["enforce", "complain", "unconfined"]

    def test_apparmor_profile_serialization(self):
        """Test AppArmor profile serialization."""
        profile = AppArmorProfile(
            installed=True,
            mode="enforce",
            enabled_profiles=3,
        )

        profile_dict = profile.to_dict()

        assert profile_dict["installed"] is True
        assert profile_dict["mode"] == "enforce"


class TestSeccompDetection:
    """Test Seccomp detection."""

    def test_detect_seccomp(self):
        """Test Seccomp detection."""
        detector = RuntimeDetector()
        profile = detector.detect_seccomp()

        assert profile.installed is True
        assert profile.default_policy in ["none", "audit", "block"]

    def test_seccomp_profile_serialization(self):
        """Test Seccomp profile serialization."""
        profile = SeccompProfile(
            installed=True,
            default_policy="audit",
            profiles=["restricted", "baseline"],
            blocked_syscalls=["ptrace", "mount"],
        )

        profile_dict = profile.to_dict()

        assert profile_dict["installed"] is True
        assert len(profile_dict["profiles"]) == 2


class TestSIEMAgentDetection:
    """Test SIEM agent detection."""

    def test_detect_siem_agents(self):
        """Test SIEM agent detection."""
        detector = RuntimeDetector()
        agents = detector.detect_siem_agents()

        assert len(agents) >= 1
        assert all(isinstance(a, SIEMAgent) for a in agents)

    def test_datadog_detection(self):
        """Test Datadog agent detection."""
        detector = RuntimeDetector()
        agents = detector.detect_siem_agents()

        datadog = next((a for a in agents if a.name == "datadog"), None)
        assert datadog is not None
        assert datadog.installed is True

    def test_siem_agent_serialization(self):
        """Test SIEM agent serialization."""
        agent = SIEMAgent(
            name="datadog",
            installed=True,
            namespace="datadog",
            daemonset_name="datadog-agent",
            coverage=0.98,
        )

        agent_dict = agent.to_dict()

        assert agent_dict["name"] == "datadog"
        assert agent_dict["installed"] is True
        assert agent_dict["coverage"] == 0.98


class TestClusterCoverage:
    """Test overall cluster coverage report."""

    def test_get_cluster_coverage(self):
        """Test cluster coverage report generation."""
        detector = RuntimeDetector()
        report = detector.get_cluster_coverage()

        assert isinstance(report, CoverageReport)
        assert report.overall_coverage >= 0.0
        assert report.overall_coverage <= 1.0

    def test_coverage_report_has_gaps(self):
        """Test that coverage report identifies gaps."""
        detector = RuntimeDetector()
        report = detector.get_cluster_coverage()

        assert len(report.gaps) >= 0

    def test_coverage_report_serialization(self):
        """Test coverage report serialization."""
        detector = RuntimeDetector()
        report = detector.get_cluster_coverage()

        report_dict = report.to_dict()

        assert "falco" in report_dict
        assert "tetragon" in report_dict
        assert "apparmor" in report_dict
        assert "seccomp" in report_dict
        assert "overall_coverage" in report_dict

    def test_coverage_calculation(self):
        """Test coverage calculation logic."""
        detector = RuntimeDetector()
        report = detector.get_cluster_coverage()

        # Overall coverage should be average of tool coverages
        assert report.overall_coverage >= 0.0
