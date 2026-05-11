"""Tests for GCP IAM privilege escalation techniques."""

import pytest

from kubexhunt.cloud_iam.gcp_iam import (
    GCPEscalationPath,
    GCPIAMAttacker,
)
from kubexhunt.core.graph import RelationType


@pytest.fixture
def gcp_attacker():
    """Create GCPIAMAttacker instance."""
    return GCPIAMAttacker()


class TestGCPEscalationPathDataclass:
    """Test GCPEscalationPath dataclass."""

    def test_escalation_path_serialization(self):
        """Test GCPEscalationPath to_dict serialization."""
        path = GCPEscalationPath(
            start_sa="app-sa@project.iam.gserviceaccount.com",
            escalation_steps=[
                "iam.serviceAccountKeys.create",
                "iam.serviceAccounts.actAs",
            ],
            final_access="roles/owner",
            complexity="MEDIUM",
        )
        d = path.to_dict()
        assert d["start_sa"] == "app-sa@project.iam.gserviceaccount.com"
        assert d["final_access"] == "roles/owner"
        assert len(d["escalation_steps"]) == 2

    def test_escalation_path_defaults(self):
        """Test GCPEscalationPath default values."""
        path = GCPEscalationPath(start_sa="sa@project.iam.gserviceaccount.com")
        assert path.final_access == "roles/owner"
        assert path.complexity == "MEDIUM"


class TestEnumerateEscalationPaths:
    """Test GCP escalation path enumeration."""

    def test_enumerate_escalation_paths(self, gcp_attacker):
        """Test escalation path enumeration."""
        paths = gcp_attacker.enumerate_escalation_paths("test-sa@project.iam.gserviceaccount.com")
        assert len(paths) > 0
        assert all(isinstance(p, GCPEscalationPath) for p in paths)

    def test_paths_have_required_fields(self, gcp_attacker):
        """Test all paths have required fields."""
        paths = gcp_attacker.enumerate_escalation_paths("test-sa@project.iam.gserviceaccount.com")
        for path in paths:
            assert path.start_sa
            assert path.escalation_steps
            assert path.final_access

    def test_multiple_paths_enumerated(self, gcp_attacker):
        """Test multiple escalation paths enumerated."""
        paths = gcp_attacker.enumerate_escalation_paths("test-sa@project.iam.gserviceaccount.com")
        assert len(paths) >= 2


class TestSAKeyBackdoorChain:
    """Test service account key backdoor chain."""

    def test_generate_sa_key_backdoor_chain(self, gcp_attacker):
        """Test SA key backdoor chain generation."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        assert chain is not None
        assert chain.path_id
        assert len(chain.steps) > 0

    def test_sa_key_chain_structure(self, gcp_attacker):
        """Test SA key chain structure."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        assert chain.title
        assert chain.description
        assert "backdoor" in chain.title.lower() or "key" in chain.title.lower()

    def test_sa_key_creates_key_file(self, gcp_attacker):
        """Test SA key chain creates key file."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        # Should have gcloud iam command to create keys
        has_key_creation = any("keys create" in step.command for step in chain.steps)
        assert has_key_creation

    def test_sa_key_chain_has_auth_step(self, gcp_attacker):
        """Test SA key chain includes authentication step."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        # Should have gcloud auth activate-service-account
        has_auth = any("activate-service-account" in step.command for step in chain.steps)
        assert has_auth

    def test_sa_key_correct_relation(self, gcp_attacker):
        """Test SA key chain uses correct relation."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        for step in chain.steps:
            assert step.relation == RelationType.CAN_CREATE_IAM_BACKDOOR

    def test_sa_key_trivial_complexity(self, gcp_attacker):
        """Test SA key backdoor is trivial complexity."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        assert chain.complexity == "TRIVIAL"


class TestOrgAdminChain:
    """Test organization-level admin access chain."""

    def test_generate_org_admin_chain(self, gcp_attacker):
        """Test org admin chain generation."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        assert chain is not None
        assert len(chain.steps) > 0

    def test_org_admin_chain_structure(self, gcp_attacker):
        """Test org admin chain structure."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        assert chain.path_id
        assert chain.title
        assert "org" in chain.title.lower() or "admin" in chain.title.lower()

    def test_org_admin_sets_iam_policy(self, gcp_attacker):
        """Test org admin chain sets IAM policy."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        # Should have set-iam-policy command
        has_policy = any("set-iam-policy" in step.command.lower() for step in chain.steps)
        assert has_policy

    def test_org_admin_binds_owner_role(self, gcp_attacker):
        """Test org admin chain binds owner role."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        # Should assign roles/owner
        has_owner = any("roles/owner" in step.command for step in chain.steps)
        assert has_owner

    def test_org_admin_correct_relation(self, gcp_attacker):
        """Test org admin chain uses correct relation."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        for step in chain.steps:
            assert step.relation == RelationType.CAN_CREATE_IAM_BACKDOOR

    def test_org_admin_medium_complexity(self, gcp_attacker):
        """Test org admin chain is medium complexity."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        assert chain.complexity == "MEDIUM"


class TestFindOverprivilegedBindings:
    """Test overprivileged binding discovery."""

    def test_find_overprivileged_bindings(self, gcp_attacker):
        """Test overprivileged binding enumeration."""
        bindings = gcp_attacker.find_overprivileged_bindings()
        assert isinstance(bindings, list)
        assert len(bindings) > 0

    def test_bindings_have_required_fields(self, gcp_attacker):
        """Test bindings have required fields."""
        bindings = gcp_attacker.find_overprivileged_bindings()
        for binding in bindings:
            assert len(binding) == 3  # (sa_email, role, risk)
            sa_email, role, risk = binding
            assert "@" in sa_email  # Valid email format
            assert "roles/" in role
            assert risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_bindings_include_critical(self, gcp_attacker):
        """Test bindings include critical risk levels."""
        bindings = gcp_attacker.find_overprivileged_bindings()
        critical = [b for b in bindings if b[2] == "CRITICAL"]
        assert len(critical) > 0

    def test_bindings_have_owner_role(self, gcp_attacker):
        """Test at least some bindings have owner role."""
        bindings = gcp_attacker.find_overprivileged_bindings()
        owner_bindings = [b for b in bindings if "owner" in b[1].lower()]
        assert len(owner_bindings) > 0


class TestMITREMappings:
    """Test MITRE ATT&CK technique mappings."""

    def test_sa_key_chain_has_mitre(self, gcp_attacker):
        """Test SA key chain includes MITRE techniques."""
        chain = gcp_attacker.generate_sa_key_backdoor_chain("test-sa@project.iam.gserviceaccount.com")
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(isinstance(t, str) for t in step.mitre_techniques)

    def test_org_admin_chain_has_mitre(self, gcp_attacker):
        """Test org admin chain includes MITRE techniques."""
        chain = gcp_attacker.generate_org_admin_chain("test-project")
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(t.startswith("T") for t in step.mitre_techniques)


class TestGCPIAMAttackerIntegration:
    """Integration tests for GCP IAM attacker."""

    def test_full_gcp_escalation_workflow(self, gcp_attacker):
        """Test complete GCP escalation workflow."""
        # Enumerate paths
        paths = gcp_attacker.enumerate_escalation_paths("app-sa@project.iam.gserviceaccount.com")
        assert len(paths) > 0

        # Generate backdoor chains
        key_chain = gcp_attacker.generate_sa_key_backdoor_chain("app-sa@project.iam.gserviceaccount.com")
        admin_chain = gcp_attacker.generate_org_admin_chain("test-project")
        assert key_chain is not None
        assert admin_chain is not None

        # Find overprivileged bindings
        bindings = gcp_attacker.find_overprivileged_bindings()
        assert len(bindings) > 0

    def test_sa_key_enables_org_admin(self, gcp_attacker):
        """Test SA key backdoor enables org admin access."""
        # Create key backdoor for persistent access
        key_chain = gcp_attacker.generate_sa_key_backdoor_chain("sa@project.iam.gserviceaccount.com")
        assert key_chain is not None

        # Then use it to escalate to org admin
        admin_chain = gcp_attacker.generate_org_admin_chain("project")
        assert admin_chain is not None

        # Chains should be chained together in real attack
        assert key_chain.path_id
        assert admin_chain.path_id
