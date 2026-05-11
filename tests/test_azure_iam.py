"""Tests for Azure IAM privilege escalation techniques."""

import pytest

from kubexhunt.cloud_iam.azure_iam import (
    AzureEscalationPath,
    AzureIAMAttacker,
)
from kubexhunt.core.graph import RelationType


@pytest.fixture
def azure_attacker():
    """Create AzureIAMAttacker instance."""
    return AzureIAMAttacker()


class TestAzureEscalationPathDataclass:
    """Test AzureEscalationPath dataclass."""

    def test_escalation_path_serialization(self):
        """Test AzureEscalationPath to_dict serialization."""
        path = AzureEscalationPath(
            start_identity="app-identity",
            escalation_steps=[
                "microsoft.directory/applications/credentials/create",
                "microsoft.directory/servicePrincipals.impersonation/appRole/selfGrantAppRole",
            ],
            final_access="Global Administrator",
            complexity="EASY",
        )
        d = path.to_dict()
        assert d["start_identity"] == "app-identity"
        assert d["final_access"] == "Global Administrator"
        assert len(d["escalation_steps"]) == 2

    def test_escalation_path_defaults(self):
        """Test AzureEscalationPath default values."""
        path = AzureEscalationPath(start_identity="identity1")
        assert path.final_access == "Global Administrator"
        assert path.complexity == "MEDIUM"


class TestEnumerateEscalationPaths:
    """Test Azure escalation path enumeration."""

    def test_enumerate_escalation_paths(self, azure_attacker):
        """Test escalation path enumeration."""
        paths = azure_attacker.enumerate_escalation_paths("test-identity")
        assert len(paths) > 0
        assert all(isinstance(p, AzureEscalationPath) for p in paths)

    def test_paths_have_required_fields(self, azure_attacker):
        """Test all paths have required fields."""
        paths = azure_attacker.enumerate_escalation_paths("test-identity")
        for path in paths:
            assert path.start_identity
            assert path.escalation_steps
            assert path.final_access

    def test_multiple_escalation_paths(self, azure_attacker):
        """Test multiple escalation paths enumerated."""
        paths = azure_attacker.enumerate_escalation_paths("test-identity")
        assert len(paths) >= 2


class TestAppRegistrationBackdoorChain:
    """Test app registration backdoor chain."""

    def test_generate_app_registration_backdoor(self, azure_attacker):
        """Test app registration backdoor chain generation."""
        chain = azure_attacker.generate_app_registration_backdoor()
        assert chain is not None
        assert chain.path_id
        assert len(chain.steps) > 0

    def test_app_reg_chain_structure(self, azure_attacker):
        """Test app registration chain structure."""
        chain = azure_attacker.generate_app_registration_backdoor()
        assert chain.title
        assert chain.description
        assert "app" in chain.title.lower() or "registration" in chain.title.lower()

    def test_app_reg_creates_credentials(self, azure_attacker):
        """Test app registration chain creates credentials."""
        chain = azure_attacker.generate_app_registration_backdoor()
        # Should have az ad app credential reset command
        has_credential = any("credential reset" in step.command.lower() for step in chain.steps)
        assert has_credential

    def test_app_reg_grants_consent(self, azure_attacker):
        """Test app registration chain grants admin consent."""
        chain = azure_attacker.generate_app_registration_backdoor()
        # Should have admin-consent command
        has_consent = any("admin-consent" in step.command or "consent" in step.command.lower() for step in chain.steps)
        assert has_consent

    def test_app_reg_enables_login(self, azure_attacker):
        """Test app registration chain enables login."""
        chain = azure_attacker.generate_app_registration_backdoor()
        # Should have az login command
        has_login = any("az login" in step.command for step in chain.steps)
        assert has_login

    def test_app_reg_correct_relation(self, azure_attacker):
        """Test app registration chain uses correct relation."""
        chain = azure_attacker.generate_app_registration_backdoor()
        for step in chain.steps:
            assert step.relation == RelationType.CAN_CREATE_IAM_BACKDOOR

    def test_app_reg_easy_complexity(self, azure_attacker):
        """Test app registration backdoor is easy complexity."""
        chain = azure_attacker.generate_app_registration_backdoor()
        assert chain.complexity == "EASY"


class TestManagedIdentityChain:
    """Test managed identity escalation chain."""

    def test_generate_managed_identity_chain(self, azure_attacker):
        """Test managed identity escalation chain."""
        chain = azure_attacker.generate_managed_identity_chain()
        assert chain is not None
        assert len(chain.steps) > 0

    def test_managed_identity_chain_structure(self, azure_attacker):
        """Test managed identity chain structure."""
        chain = azure_attacker.generate_managed_identity_chain()
        assert chain.path_id
        assert chain.title
        assert "managed identity" in chain.title.lower() or "identity" in chain.title.lower()

    def test_managed_identity_assigns_owner(self, azure_attacker):
        """Test managed identity chain assigns owner role."""
        chain = azure_attacker.generate_managed_identity_chain()
        # Should have role assignment command
        has_assignment = any("role assignment create" in step.command.lower() for step in chain.steps)
        assert has_assignment

    def test_managed_identity_assigns_owner_role(self, azure_attacker):
        """Test owner role is assigned."""
        chain = azure_attacker.generate_managed_identity_chain()
        # Should assign Owner role
        has_owner = any("Owner" in step.command for step in chain.steps)
        assert has_owner

    def test_managed_identity_correct_relation(self, azure_attacker):
        """Test managed identity chain uses correct relation."""
        chain = azure_attacker.generate_managed_identity_chain()
        for step in chain.steps:
            assert step.relation == RelationType.CAN_CREATE_IAM_BACKDOOR

    def test_managed_identity_trivial_complexity(self, azure_attacker):
        """Test managed identity is trivial complexity."""
        chain = azure_attacker.generate_managed_identity_chain()
        assert chain.complexity == "TRIVIAL"


class TestFindPrivilegedAppRegistrations:
    """Test privileged app registration discovery."""

    def test_find_privileged_app_registrations(self, azure_attacker):
        """Test privileged app registration enumeration."""
        apps = azure_attacker.find_privileged_app_registrations()
        assert isinstance(apps, list)
        assert len(apps) > 0

    def test_apps_have_required_fields(self, azure_attacker):
        """Test apps have required fields."""
        apps = azure_attacker.find_privileged_app_registrations()
        for app in apps:
            assert "app_id" in app
            assert "name" in app
            assert "admin_permissions" in app
            assert "risk" in app

    def test_apps_include_critical_risk(self, azure_attacker):
        """Test at least some apps marked as critical risk."""
        apps = azure_attacker.find_privileged_app_registrations()
        critical = [a for a in apps if a.get("risk") == "CRITICAL"]
        assert len(critical) > 0

    def test_apps_have_graph_permissions(self, azure_attacker):
        """Test apps have Microsoft Graph permissions."""
        apps = azure_attacker.find_privileged_app_registrations()
        graph_apps = [a for a in apps if "Microsoft.Graph" in a.get("admin_permissions", "")]
        assert len(graph_apps) > 0


class TestMITREMappings:
    """Test MITRE ATT&CK technique mappings."""

    def test_app_reg_chain_has_mitre(self, azure_attacker):
        """Test app registration chain includes MITRE techniques."""
        chain = azure_attacker.generate_app_registration_backdoor()
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(isinstance(t, str) for t in step.mitre_techniques)

    def test_managed_identity_chain_has_mitre(self, azure_attacker):
        """Test managed identity chain includes MITRE techniques."""
        chain = azure_attacker.generate_managed_identity_chain()
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(t.startswith("T") for t in step.mitre_techniques)


class TestAzureIAMAttackerIntegration:
    """Integration tests for Azure IAM attacker."""

    def test_full_azure_escalation_workflow(self, azure_attacker):
        """Test complete Azure escalation workflow."""
        # Enumerate paths
        paths = azure_attacker.enumerate_escalation_paths("app-identity")
        assert len(paths) > 0

        # Generate backdoor chains
        app_chain = azure_attacker.generate_app_registration_backdoor()
        mi_chain = azure_attacker.generate_managed_identity_chain()
        assert app_chain is not None
        assert mi_chain is not None

        # Find privileged apps
        apps = azure_attacker.find_privileged_app_registrations()
        assert len(apps) > 0

    def test_app_registration_enables_global_admin(self, azure_attacker):
        """Test app registration leads to global administrator."""
        chain = azure_attacker.generate_app_registration_backdoor()
        # Final node should indicate global admin access
        assert any("admin" in node.lower() or "global" in node.lower() for node in chain.nodes)

    def test_managed_identity_subscription_escalation(self, azure_attacker):
        """Test managed identity escalates to subscription level."""
        chain = azure_attacker.generate_managed_identity_chain()
        # Should operate at subscription scope
        assert any("subscription" in step.command.lower() or "scope" in step.command.lower() for step in chain.steps)
