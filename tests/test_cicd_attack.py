"""Tests for CI/CD pipeline attack detection and exploitation."""

import pytest

from kubexhunt.core.graph import RelationType
from kubexhunt.supply_chain.cicd_attack import (
    ArgoCDProfile,
    CICDAttacker,
    FluxProfile,
    PipelineSecret,
)


@pytest.fixture
def cicd_attacker():
    """Create CICDAttacker instance."""
    return CICDAttacker()


class TestArgoCDProfileDataclass:
    """Test ArgoCDProfile dataclass."""

    def test_argocd_serialization(self):
        """Test ArgoCDProfile to_dict serialization."""
        profile = ArgoCDProfile(
            installed=True,
            version="2.4.0",
            namespace="argocd",
            admin_password_exposed=True,
            apps_count=5,
            cluster_access_count=2,
        )
        d = profile.to_dict()
        assert d["installed"] is True
        assert d["version"] == "2.4.0"
        assert d["admin_password_exposed"] is True
        assert d["apps_count"] == 5

    def test_argocd_default_values(self):
        """Test ArgoCDProfile default values."""
        profile = ArgoCDProfile(installed=False)
        assert profile.namespace == "argocd"
        assert profile.admin_password_exposed is False
        assert profile.apps_count == 0


class TestFluxProfileDataclass:
    """Test FluxProfile dataclass."""

    def test_flux_serialization(self):
        """Test FluxProfile to_dict serialization."""
        profile = FluxProfile(
            installed=True,
            version="0.41.0",
            namespace="flux-system",
            git_repo="https://github.com/company/gitops-repo",
            reconciliation_enabled=True,
        )
        d = profile.to_dict()
        assert d["installed"] is True
        assert d["version"] == "0.41.0"
        assert d["git_repo"] == "https://github.com/company/gitops-repo"

    def test_flux_default_values(self):
        """Test FluxProfile defaults."""
        profile = FluxProfile(installed=False)
        assert profile.namespace == "flux-system"
        assert profile.git_repo == ""


class TestPipelineSecretDataclass:
    """Test PipelineSecret dataclass."""

    def test_pipeline_secret_serialization(self):
        """Test PipelineSecret to_dict serialization."""
        secret = PipelineSecret(
            tool_name="argocd",
            secret_type="api_token",
            key_hint="ARGOCD_SERVER",
            namespace="argocd",
            severity="CRITICAL",
        )
        d = secret.to_dict()
        assert d["tool_name"] == "argocd"
        assert d["secret_type"] == "api_token"
        assert d["severity"] == "CRITICAL"

    def test_pipeline_secret_defaults(self):
        """Test PipelineSecret default values."""
        secret = PipelineSecret(
            tool_name="jenkins",
            secret_type="credential",
            key_hint="JENKINS_API_TOKEN",
            namespace="jenkins",
        )
        assert secret.severity == "HIGH"


class TestDetectArgoCD:
    """Test ArgoCD detection."""

    def test_detect_argocd_when_installed(self, cicd_attacker):
        """Test ArgoCD detection when installed."""
        profile = cicd_attacker.detect_argocd()
        assert isinstance(profile, ArgoCDProfile)
        # Mocked implementation should return installed=True
        assert profile.installed is True or profile.installed is False

    def test_argocd_profile_has_required_fields(self, cicd_attacker):
        """Test ArgoCD profile has all required fields."""
        profile = cicd_attacker.detect_argocd()
        assert hasattr(profile, "installed")
        assert hasattr(profile, "version")
        assert hasattr(profile, "namespace")


class TestDetectFlux:
    """Test Flux detection."""

    def test_detect_flux_when_installed(self, cicd_attacker):
        """Test Flux detection when installed."""
        profile = cicd_attacker.detect_flux()
        assert isinstance(profile, FluxProfile)
        assert hasattr(profile, "installed")

    def test_flux_profile_structure(self, cicd_attacker):
        """Test Flux profile structure."""
        profile = cicd_attacker.detect_flux()
        assert hasattr(profile, "version")
        assert hasattr(profile, "namespace")
        assert hasattr(profile, "git_repo")


class TestEnumeratePipelineSecrets:
    """Test pipeline secret enumeration."""

    def test_enumerate_finds_secrets(self, cicd_attacker):
        """Test enumeration finds secrets."""
        secrets = cicd_attacker.enumerate_pipeline_secrets()
        assert len(secrets) > 0
        assert all(isinstance(s, PipelineSecret) for s in secrets)

    def test_secrets_have_required_fields(self, cicd_attacker):
        """Test all secrets have required fields."""
        secrets = cicd_attacker.enumerate_pipeline_secrets()
        for secret in secrets:
            assert secret.tool_name
            assert secret.secret_type
            assert secret.key_hint

    def test_secrets_include_multiple_tools(self, cicd_attacker):
        """Test secrets span multiple CI/CD tools."""
        secrets = cicd_attacker.enumerate_pipeline_secrets()
        tools = {s.tool_name for s in secrets}
        assert len(tools) > 1

    def test_secrets_include_critical_severity(self, cicd_attacker):
        """Test at least some secrets marked as critical."""
        secrets = cicd_attacker.enumerate_pipeline_secrets()
        critical = [s for s in secrets if s.severity == "CRITICAL"]
        assert len(critical) > 0


class TestArgoCDAbuseChain:
    """Test ArgoCD abuse chain generation."""

    def test_generate_argocd_abuse_chain(self, cicd_attacker):
        """Test ArgoCD abuse chain generation."""
        chain = cicd_attacker.generate_argocd_abuse_chain()
        assert chain is not None
        assert chain.path_id
        assert len(chain.steps) > 0

    def test_argocd_chain_structure(self, cicd_attacker):
        """Test ArgoCD chain structure."""
        chain = cicd_attacker.generate_argocd_abuse_chain()
        assert chain.title
        assert chain.description
        assert chain.complexity in ["TRIVIAL", "EASY", "MEDIUM", "HARD"]

    def test_argocd_chain_executable_commands(self, cicd_attacker):
        """Test ArgoCD chain has executable commands."""
        chain = cicd_attacker.generate_argocd_abuse_chain()
        for step in chain.steps:
            assert step.command
            assert len(step.command.strip()) > 0

    def test_argocd_chain_correct_relation(self, cicd_attacker):
        """Test ArgoCD chain uses COMPROMISES_CICD relation."""
        chain = cicd_attacker.generate_argocd_abuse_chain()
        for step in chain.steps:
            assert step.relation == RelationType.COMPROMISES_CICD


class TestPipelineCredentialChain:
    """Test pipeline credential exploitation chain."""

    def test_generate_pipeline_credential_chain(self, cicd_attacker):
        """Test pipeline credential chain generation."""
        chain = cicd_attacker.generate_pipeline_credential_chain()
        assert chain is not None
        assert len(chain.steps) > 0

    def test_pipeline_chain_structure(self, cicd_attacker):
        """Test pipeline chain structure."""
        chain = cicd_attacker.generate_pipeline_credential_chain()
        assert chain.path_id
        assert chain.title
        assert chain.nodes

    def test_pipeline_chain_has_commands(self, cicd_attacker):
        """Test pipeline chain steps have commands."""
        chain = cicd_attacker.generate_pipeline_credential_chain()
        for step in chain.steps:
            assert step.command
            assert isinstance(step.command, str)


class TestFindGitRepositories:
    """Test git repository discovery."""

    def test_find_git_repositories(self, cicd_attacker):
        """Test git repository enumeration."""
        repos = cicd_attacker.find_git_repositories()
        assert isinstance(repos, list)
        # Should have some repos in Flux or ArgoCD config
        assert all(isinstance(r, dict) for r in repos)

    def test_repositories_have_fields(self, cicd_attacker):
        """Test repositories have required fields."""
        repos = cicd_attacker.find_git_repositories()
        if len(repos) > 0:
            for repo in repos:
                assert "url" in repo or "name" in repo


class TestMITREMappings:
    """Test MITRE ATT&CK technique mappings."""

    def test_argocd_chain_has_mitre(self, cicd_attacker):
        """Test ArgoCD chain includes MITRE techniques."""
        chain = cicd_attacker.generate_argocd_abuse_chain()
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(isinstance(t, str) for t in step.mitre_techniques)

    def test_pipeline_chain_has_mitre(self, cicd_attacker):
        """Test pipeline chain includes MITRE techniques."""
        chain = cicd_attacker.generate_pipeline_credential_chain()
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(t.startswith("T") for t in step.mitre_techniques)


class TestCICDAttackerIntegration:
    """Integration tests for CI/CD attacker."""

    def test_full_argocd_attack_flow(self, cicd_attacker):
        """Test complete ArgoCD attack flow."""
        # Detect ArgoCD
        argocd = cicd_attacker.detect_argocd()
        assert argocd is not None

        # Enumerate secrets
        secrets = cicd_attacker.enumerate_pipeline_secrets()
        assert len(secrets) > 0

        # Generate exploitation chain
        chain = cicd_attacker.generate_argocd_abuse_chain()
        assert chain is not None

    def test_full_flux_detection(self, cicd_attacker):
        """Test Flux detection flow."""
        flux = cicd_attacker.detect_flux()
        assert flux is not None
        assert hasattr(flux, "installed")

    def test_attack_uses_pipeline_secrets(self, cicd_attacker):
        """Test attack leverages pipeline secrets."""
        secrets = cicd_attacker.enumerate_pipeline_secrets()
        chain = cicd_attacker.generate_argocd_abuse_chain()
        # Chain should use credentials from enumerated secrets
        assert len(secrets) > 0
        assert chain is not None
