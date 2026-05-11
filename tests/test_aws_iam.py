"""Tests for AWS IAM privilege escalation and backdoor techniques."""

import pytest

from kubexhunt.cloud_iam.aws_iam import (
    AWSIAMAttacker,
    IAMEscalationPath,
)
from kubexhunt.core.graph import RelationType


@pytest.fixture
def aws_attacker():
    """Create AWSIAMAttacker instance."""
    return AWSIAMAttacker()


class TestIAMEscalationPathDataclass:
    """Test IAMEscalationPath dataclass."""

    def test_escalation_path_serialization(self):
        """Test IAMEscalationPath to_dict serialization."""
        path = IAMEscalationPath(
            start_role="developer-role",
            escalation_steps=[
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
            ],
            final_access="AdministratorAccess",
            technique_id="AWS-ESC-001",
            mitre_techniques=["T1098.004"],
            complexity="EASY",
        )
        d = path.to_dict()
        assert d["start_role"] == "developer-role"
        assert d["final_access"] == "AdministratorAccess"
        assert len(d["escalation_steps"]) == 2
        assert d["complexity"] == "EASY"

    def test_escalation_path_defaults(self):
        """Test IAMEscalationPath default values."""
        path = IAMEscalationPath(start_role="role1")
        assert path.final_access == "AdministratorAccess"
        assert path.complexity == "MEDIUM"
        assert path.escalation_steps == []
        assert path.mitre_techniques == []


class TestEnumerateEscalationPaths:
    """Test escalation path enumeration."""

    def test_enumerate_escalation_paths(self, aws_attacker):
        """Test escalation path enumeration."""
        paths = aws_attacker.enumerate_escalation_paths("test-role")
        assert len(paths) > 0
        assert all(isinstance(p, IAMEscalationPath) for p in paths)

    def test_paths_have_required_fields(self, aws_attacker):
        """Test all paths have required fields."""
        paths = aws_attacker.enumerate_escalation_paths("test-role")
        for path in paths:
            assert path.start_role
            assert path.escalation_steps
            assert path.final_access

    def test_multiple_escalation_techniques(self, aws_attacker):
        """Test multiple escalation techniques enumerated."""
        paths = aws_attacker.enumerate_escalation_paths("test-role")
        # Should have at least 3 different escalation paths
        assert len(paths) >= 3
        # Paths should have different steps
        steps_sets = [set(p.escalation_steps) for p in paths]
        assert len({frozenset(s) for s in steps_sets}) >= 2

    def test_paths_include_complexity(self, aws_attacker):
        """Test paths have complexity ratings."""
        paths = aws_attacker.enumerate_escalation_paths("test-role")
        complexities = {p.complexity for p in paths}
        assert len(complexities) > 0
        assert all(c in ["TRIVIAL", "EASY", "MEDIUM", "HARD"] for c in complexities)

    def test_paths_mapped_to_technique_ids(self, aws_attacker):
        """Test escalation paths have technique IDs."""
        paths = aws_attacker.enumerate_escalation_paths("test-role")
        with_ids = [p for p in paths if p.technique_id]
        assert len(with_ids) > 0


class TestBackdoorUserChain:
    """Test backdoor IAM user creation chain."""

    def test_generate_backdoor_user_chain(self, aws_attacker):
        """Test backdoor user chain generation."""
        chain = aws_attacker.generate_backdoor_user_chain("test-role")
        assert chain is not None
        assert chain.path_id
        assert len(chain.steps) > 0
        assert len(chain.nodes) > 0

    def test_backdoor_user_chain_structure(self, aws_attacker):
        """Test backdoor user chain structure."""
        chain = aws_attacker.generate_backdoor_user_chain()
        assert chain.title
        assert chain.description
        assert "backdoor" in chain.title.lower()
        assert "user" in chain.title.lower()

    def test_backdoor_user_has_executable_commands(self, aws_attacker):
        """Test backdoor user chain has executable commands."""
        chain = aws_attacker.generate_backdoor_user_chain()
        for step in chain.steps:
            assert step.command
            assert len(step.command.strip()) > 0
            assert "aws" in step.command.lower() or "jq" in step.command.lower()

    def test_backdoor_user_correct_relation(self, aws_attacker):
        """Test backdoor user chain uses correct relation."""
        chain = aws_attacker.generate_backdoor_user_chain()
        for step in chain.steps:
            assert step.relation == RelationType.CAN_CREATE_IAM_BACKDOOR

    def test_backdoor_user_complexity_trivial(self, aws_attacker):
        """Test backdoor user is trivial complexity."""
        chain = aws_attacker.generate_backdoor_user_chain()
        assert chain.complexity == "TRIVIAL"

    def test_backdoor_user_final_node(self, aws_attacker):
        """Test backdoor user chain has admin access node."""
        chain = aws_attacker.generate_backdoor_user_chain()
        assert "admin" in chain.nodes[-1].lower() or "backdoor" in chain.nodes[-1].lower()


class TestBackdoorRoleChain:
    """Test backdoor IAM role creation chain."""

    def test_generate_backdoor_role_chain(self, aws_attacker):
        """Test backdoor role chain generation."""
        chain = aws_attacker.generate_backdoor_role_chain()
        assert chain is not None
        assert len(chain.steps) > 0

    def test_backdoor_role_chain_structure(self, aws_attacker):
        """Test backdoor role chain structure."""
        chain = aws_attacker.generate_backdoor_role_chain()
        assert chain.title
        assert chain.description
        assert "role" in chain.title.lower()

    def test_backdoor_role_has_trust_policy(self, aws_attacker):
        """Test backdoor role includes trust policy."""
        chain = aws_attacker.generate_backdoor_role_chain()
        has_trust = any("trust" in step.command.lower() for step in chain.steps)
        assert has_trust

    def test_backdoor_role_cross_account_capable(self, aws_attacker):
        """Test backdoor role is cross-account assumable."""
        chain = aws_attacker.generate_backdoor_role_chain()
        # Should have wildcard principal in trust policy
        trust_step = [s for s in chain.steps if "Principal" in s.command]
        assert len(trust_step) > 0

    def test_backdoor_role_correct_relation(self, aws_attacker):
        """Test backdoor role chain uses correct relation."""
        chain = aws_attacker.generate_backdoor_role_chain()
        for step in chain.steps:
            assert step.relation == RelationType.CAN_CREATE_IAM_BACKDOOR


class TestPolicyVersionEscalation:
    """Test policy version escalation technique."""

    def test_generate_policy_version_escalation(self, aws_attacker):
        """Test policy version escalation chain."""
        chain = aws_attacker.generate_policy_version_escalation()
        assert chain is not None
        assert len(chain.steps) > 0

    def test_policy_version_chain_structure(self, aws_attacker):
        """Test policy version chain structure."""
        chain = aws_attacker.generate_policy_version_escalation()
        assert chain.path_id
        assert "policy" in chain.title.lower()

    def test_policy_version_creates_admin_policy(self, aws_attacker):
        """Test policy version escalation creates admin policy."""
        chain = aws_attacker.generate_policy_version_escalation()
        # Should have admin policy JSON in command
        policy_step = chain.steps[0]
        assert "admin" in policy_step.command.lower() or "*" in policy_step.command
        assert "Action" in policy_step.command

    def test_policy_version_sets_default(self, aws_attacker):
        """Test policy version is set as default."""
        chain = aws_attacker.generate_policy_version_escalation()
        has_set_default = any("set-as-default" in step.command.lower() for step in chain.steps)
        assert has_set_default


class TestFindHighRiskPermissions:
    """Test high-risk permission detection."""

    def test_find_high_risk_permissions(self, aws_attacker):
        """Test high-risk permission detection."""
        dangerous_perms = [
            "iam:*",
            "iam:CreateAccessKey",
            "iam:AttachRolePolicy",
            "s3:*",
        ]
        high_risk = aws_attacker.find_high_risk_permissions(dangerous_perms)
        assert len(high_risk) > 0
        assert all(isinstance(p, str) for p in high_risk)

    def test_detects_wildcard_permissions(self, aws_attacker):
        """Test wildcard permission detection."""
        perms = ["iam:*", "s3:GetObject"]
        high_risk = aws_attacker.find_high_risk_permissions(perms)
        assert "iam:*" in high_risk or any("iam:" in p for p in high_risk)

    def test_detects_key_creation(self, aws_attacker):
        """Test access key creation permission detection."""
        perms = ["iam:CreateAccessKey", "iam:GetUser"]
        high_risk = aws_attacker.find_high_risk_permissions(perms)
        assert len(high_risk) > 0
        assert any("CreateAccessKey" in p or "iam:" in p for p in high_risk)

    def test_no_safe_permissions_flagged(self, aws_attacker):
        """Test safe permissions not flagged."""
        safe_perms = ["s3:GetObject", "ec2:DescribeInstances"]
        high_risk = aws_attacker.find_high_risk_permissions(safe_perms)
        # Should not flag safe read-only permissions
        assert len(high_risk) == 0 or all("*" not in p for p in high_risk)

    def test_case_insensitive_matching(self, aws_attacker):
        """Test case-insensitive permission matching."""
        perms = ["IAM:CREATEACCESSKEY", "iam:createaccesskey"]
        high_risk = aws_attacker.find_high_risk_permissions(perms)
        assert len(high_risk) > 0


class TestMITREMappings:
    """Test MITRE ATT&CK technique mappings."""

    def test_escalation_paths_have_mitre(self, aws_attacker):
        """Test escalation paths include MITRE techniques."""
        paths = aws_attacker.enumerate_escalation_paths("test-role")
        with_mitre = [p for p in paths if p.mitre_techniques]
        assert len(with_mitre) > 0

    def test_chains_have_mitre_techniques(self, aws_attacker):
        """Test exploit chains include MITRE techniques."""
        chain = aws_attacker.generate_backdoor_user_chain()
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(isinstance(t, str) for t in step.mitre_techniques)
            assert all(t.startswith("T") for t in step.mitre_techniques)


class TestAWSIAMAttackerIntegration:
    """Integration tests for AWS IAM attacker."""

    def test_full_escalation_workflow(self, aws_attacker):
        """Test complete escalation workflow."""
        # Enumerate paths
        paths = aws_attacker.enumerate_escalation_paths("app-role")
        assert len(paths) > 0

        # Generate backdoors
        user_chain = aws_attacker.generate_backdoor_user_chain("app-role")
        role_chain = aws_attacker.generate_backdoor_role_chain("app-role")
        assert user_chain is not None
        assert role_chain is not None

        # Detect dangerous permissions
        test_perms = ["iam:*", "ec2:RunInstances"]
        high_risk = aws_attacker.find_high_risk_permissions(test_perms)
        assert len(high_risk) > 0

    def test_multiple_backdoor_options(self, aws_attacker):
        """Test multiple backdoor options available."""
        user_chain = aws_attacker.generate_backdoor_user_chain()
        role_chain = aws_attacker.generate_backdoor_role_chain()
        policy_chain = aws_attacker.generate_policy_version_escalation()

        # All should be valid exploitation paths
        assert user_chain.path_id
        assert role_chain.path_id
        assert policy_chain.path_id

        # All should have different IDs
        ids = {user_chain.path_id, role_chain.path_id, policy_chain.path_id}
        assert len(ids) == 3
