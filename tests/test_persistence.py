"""Tests for persistence mechanism generation."""

from kubexhunt.advanced.persistence import (
    CRDFinding,
    DaemonSetFinding,
    PersistenceChain,
    PersistenceEngine,
    PersistenceLevel,
    WebhookFinding,
)


class TestWebhookFinding:
    """Test WebhookFinding."""

    def test_webhook_finding_creation(self):
        """Test creating webhook finding."""
        finding = WebhookFinding(
            name="test-webhook",
            namespace="kube-system",
            fail_policy="Ignore",
            is_privileged=True,
            backdoor_risk="HIGH",
        )

        assert finding.name == "test-webhook"
        assert finding.fail_policy == "Ignore"
        assert finding.backdoor_risk == "HIGH"

    def test_webhook_finding_serialization(self):
        """Test webhook finding serialization."""
        finding = WebhookFinding(
            name="mutating-webhook",
            namespace="default",
            fail_policy="Fail",
            rules_count=5,
        )

        finding_dict = finding.to_dict()

        assert finding_dict["name"] == "mutating-webhook"
        assert finding_dict["fail_policy"] == "Fail"
        assert finding_dict["rules_count"] == 5


class TestDaemonSetFinding:
    """Test DaemonSetFinding."""

    def test_daemonset_finding_creation(self):
        """Test creating daemonset finding."""
        finding = DaemonSetFinding(
            name="monitoring-agent",
            namespace="kube-system",
            is_privileged=True,
            host_network=True,
            image="monitoring:latest",
            persistence_risk="HIGH",
        )

        assert finding.name == "monitoring-agent"
        assert finding.is_privileged is True
        assert finding.persistence_risk == "HIGH"

    def test_daemonset_finding_serialization(self):
        """Test daemonset finding serialization."""
        finding = DaemonSetFinding(
            name="ds",
            namespace="ns",
            is_privileged=False,
            persistence_risk="LOW",
        )

        finding_dict = finding.to_dict()

        assert finding_dict["is_privileged"] is False


class TestCRDFinding:
    """Test CRDFinding."""

    def test_crd_finding_creation(self):
        """Test creating CRD finding."""
        finding = CRDFinding(
            name="BadResource",
            group="attacker.io",
            controller_present=True,
            controller_namespace="attacker",
            persistence_risk="HIGH",
        )

        assert finding.name == "BadResource"
        assert finding.controller_present is True

    def test_crd_finding_serialization(self):
        """Test CRD finding serialization."""
        finding = CRDFinding(
            name="Custom",
            group="group.io",
            controller_present=False,
        )

        finding_dict = finding.to_dict()

        assert finding_dict["name"] == "Custom"
        assert finding_dict["controller_present"] is False


class TestPersistenceChain:
    """Test PersistenceChain."""

    def test_persistence_chain_creation(self):
        """Test creating persistence chain."""
        chain = PersistenceChain(
            technique_id="PER-001",
            name="Test Persistence",
            description="Test persistence mechanism",
            persistence_level=PersistenceLevel.CLUSTER,
            survives_restarts=True,
            survives_upgrades=True,
        )

        assert chain.technique_id == "PER-001"
        assert chain.persistence_level == PersistenceLevel.CLUSTER
        assert chain.survives_upgrades is True

    def test_persistence_chain_serialization(self):
        """Test persistence chain serialization."""
        chain = PersistenceChain(
            technique_id="PER-002",
            name="Test",
            description="Desc",
            persistence_level=PersistenceLevel.POD,
            survives_restarts=False,
        )

        chain_dict = chain.to_dict()

        assert chain_dict["technique_id"] == "PER-002"
        assert chain_dict["persistence_level"] == "pod"

    def test_persistence_chain_mitre_mapping(self):
        """Test persistence chain has MITRE techniques."""
        chain = PersistenceChain(
            technique_id="PER-003",
            name="Test",
            description="Test",
            persistence_level=PersistenceLevel.CLUSTER,
            mitre_techniques=["T1053.007", "T1137"],
        )

        assert len(chain.mitre_techniques) == 2
        assert "T1053.007" in chain.mitre_techniques


class TestFindSuspiciousWebhooks:
    """Test webhook detection."""

    def test_find_suspicious_webhooks(self):
        """Test finding suspicious webhooks."""
        engine = PersistenceEngine()
        findings = engine.find_suspicious_webhooks()

        assert len(findings) >= 1
        assert all(isinstance(f, WebhookFinding) for f in findings)

    def test_webhook_findings_include_fail_policy(self):
        """Test webhook findings include fail policy."""
        engine = PersistenceEngine()
        findings = engine.find_suspicious_webhooks()

        for finding in findings:
            assert hasattr(finding, "fail_policy")


class TestFindPersistentDaemonSets:
    """Test DaemonSet persistence detection."""

    def test_find_persistent_daemonsets(self):
        """Test finding persistent daemonsets."""
        engine = PersistenceEngine()
        findings = engine.find_persistent_daemonsets()

        assert len(findings) >= 1
        assert all(isinstance(f, DaemonSetFinding) for f in findings)

    def test_daemonset_findings_include_risk(self):
        """Test daemonset findings include risk."""
        engine = PersistenceEngine()
        findings = engine.find_persistent_daemonsets()

        for finding in findings:
            assert finding.persistence_risk in ["LOW", "MEDIUM", "HIGH"]


class TestFindMaliciousCRDs:
    """Test CRD persistence detection."""

    def test_find_malicious_crds(self):
        """Test finding malicious CRDs."""
        engine = PersistenceEngine()
        findings = engine.find_malicious_crds()

        assert len(findings) >= 0
        assert all(isinstance(f, CRDFinding) for f in findings)


class TestGenerateWebhookBackdoor:
    """Test webhook backdoor generation."""

    def test_generate_webhook_backdoor(self):
        """Test generating webhook backdoor chain."""
        engine = PersistenceEngine()
        chain = engine.generate_webhook_backdoor()

        assert chain.technique_id == "PER-001"
        assert chain.persistence_level == PersistenceLevel.CLUSTER
        assert chain.survives_upgrades is True

    def test_webhook_backdoor_has_steps(self):
        """Test webhook backdoor has steps."""
        engine = PersistenceEngine()
        chain = engine.generate_webhook_backdoor()

        assert len(chain.steps) >= 1
        assert all(hasattr(s, "command") for s in chain.steps)

    def test_webhook_backdoor_has_removal_commands(self):
        """Test webhook backdoor has removal commands."""
        engine = PersistenceEngine()
        chain = engine.generate_webhook_backdoor()

        assert len(chain.removal_commands) >= 1


class TestGenerateDaemonSetPersistence:
    """Test DaemonSet persistence generation."""

    def test_generate_daemonset_persistence(self):
        """Test generating DaemonSet persistence chain."""
        engine = PersistenceEngine()
        chain = engine.generate_daemonset_persistence()

        assert chain.technique_id == "PER-002"
        assert chain.persistence_level == PersistenceLevel.NODE
        assert chain.survives_restarts is True

    def test_daemonset_persistence_has_kubectl_commands(self):
        """Test DaemonSet chain includes kubectl."""
        engine = PersistenceEngine()
        chain = engine.generate_daemonset_persistence()
        script = chain.to_bash_script()

        assert "kubectl" in script


class TestGenerateCRDPersistence:
    """Test CRD persistence generation."""

    def test_generate_crd_persistence(self):
        """Test generating CRD persistence chain."""
        engine = PersistenceEngine()
        chain = engine.generate_crd_persistence()

        assert chain.technique_id == "PER-003"
        assert chain.persistence_level == PersistenceLevel.CLUSTER

    def test_crd_persistence_includes_controller(self):
        """Test CRD persistence includes controller."""
        engine = PersistenceEngine()
        chain = engine.generate_crd_persistence()
        script = chain.to_bash_script()

        assert "controller" in script.lower() or "CustomResourceDefinition" in script


class TestGenerateCronJobPersistence:
    """Test CronJob persistence generation."""

    def test_generate_cron_job_persistence(self):
        """Test generating CronJob persistence chain."""
        engine = PersistenceEngine()
        chain = engine.generate_cron_job_persistence()

        assert chain.technique_id == "PER-004"
        assert chain.persistence_level == PersistenceLevel.CLUSTER

    def test_cron_job_persistence_includes_schedule(self):
        """Test CronJob includes schedule."""
        engine = PersistenceEngine()
        chain = engine.generate_cron_job_persistence()
        script = chain.to_bash_script()

        assert "schedule" in script or "cronjob" in script.lower()


class TestGenerateAllPersistenceChains:
    """Test generating all persistence chains."""

    def test_generate_all_persistence_chains(self):
        """Test generating all persistence chains."""
        engine = PersistenceEngine()
        chains = engine.generate_all_persistence_chains()

        assert len(chains) >= 3
        assert all(isinstance(c, PersistenceChain) for c in chains)

    def test_all_chains_have_unique_ids(self):
        """Test all chains have unique IDs."""
        engine = PersistenceEngine()
        chains = engine.generate_all_persistence_chains()

        ids = [c.technique_id for c in chains]
        assert len(ids) == len(set(ids))


class TestPersistenceChainBashScriptGeneration:
    """Test bash script generation from persistence chain."""

    def test_to_bash_script(self):
        """Test generating bash script from persistence chain."""
        engine = PersistenceEngine()
        chain = engine.generate_webhook_backdoor()
        script = chain.to_bash_script()

        assert "#!/bin/bash" in script
        assert chain.technique_id in script
        assert "persistence" in script.lower()

    def test_script_includes_removal_commands(self):
        """Test script includes removal commands."""
        engine = PersistenceEngine()
        chain = engine.generate_daemonset_persistence()
        script = chain.to_bash_script()

        # Should mention removal
        assert "remove" in script.lower() or "cleanup" in script.lower() or "delete" in script.lower()
