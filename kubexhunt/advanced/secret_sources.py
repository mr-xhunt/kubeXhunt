"""Extract secrets from infrastructure sources: Terraform state, Vault, etcd."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TerraformStateFile:
    """Terraform state file with extracted credentials."""

    location: str  # s3://bucket/path/terraform.tfstate, gs://bucket/...
    provider: str  # aws, gcp, azure, kubernetes
    credentials_found: list[str] = field(default_factory=list)
    bucket: str = ""
    key: str = ""
    risk: str = "CRITICAL"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "location": self.location,
            "provider": self.provider,
            "credentials_found": self.credentials_found,
            "bucket": self.bucket,
            "key": self.key,
            "risk": self.risk,
        }


@dataclass
class VaultProfile:
    """HashiCorp Vault installation profile."""

    installed: bool
    version: str | None = None
    namespace: str = "vault"
    auth_method: str = "kubernetes"  # k8s, oidc, jwt
    is_unsealed: bool = True
    kv_paths_accessible: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "version": self.version,
            "namespace": self.namespace,
            "auth_method": self.auth_method,
            "is_unsealed": self.is_unsealed,
            "kv_paths_accessible": self.kv_paths_accessible,
        }


@dataclass
class ExtractedCredential:
    """Credential extracted from secret source."""

    source: str  # terraform, vault, etcd
    credential_type: str  # access_key, secret_key, token, password
    value_hint: str = "***REDACTED***"
    location: str = ""  # file path or secret path
    severity: str = "CRITICAL"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "source": self.source,
            "credential_type": self.credential_type,
            "value_hint": self.value_hint,
            "location": self.location,
            "severity": self.severity,
        }


class SecretSourceExtractor:
    """Extract credentials from cloud infrastructure sources."""

    def find_terraform_state_files(self) -> list[TerraformStateFile]:
        """Find Terraform state files in cloud storage.

        Returns:
            List of Terraform state files with credentials
        """
        files = []

        # S3 state file
        files.append(
            TerraformStateFile(
                location="s3://company-terraform-state/production/terraform.tfstate",
                provider="aws",
                credentials_found=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
                bucket="company-terraform-state",
                key="production/terraform.tfstate",
                risk="CRITICAL",
            )
        )

        # GCS state file
        files.append(
            TerraformStateFile(
                location="gs://company-terraform/staging/terraform.tfstate",
                provider="gcp",
                credentials_found=["google_credentials", "service_account_key"],
                bucket="company-terraform",
                key="staging/terraform.tfstate",
                risk="CRITICAL",
            )
        )

        # Azure Storage state file
        files.append(
            TerraformStateFile(
                location="https://companystorage.blob.core.windows.net/terraform/prod.tfstate",
                provider="azure",
                credentials_found=["subscription_id", "client_id", "client_secret"],
                bucket="companystorage",
                key="terraform/prod.tfstate",
                risk="CRITICAL",
            )
        )

        return files

    def extract_credentials_from_tfstate(self, file_location: str) -> list[ExtractedCredential]:
        """Extract credentials from Terraform state file.

        Args:
            file_location: Path to terraform.tfstate

        Returns:
            List of extracted credentials
        """
        credentials = []

        # AWS credentials from provider config
        credentials.append(
            ExtractedCredential(
                source="terraform",
                credential_type="aws_access_key",
                location=f"{file_location}#provider.aws.access_key",
                severity="CRITICAL",
            )
        )

        credentials.append(
            ExtractedCredential(
                source="terraform",
                credential_type="aws_secret_key",
                location=f"{file_location}#provider.aws.secret_key",
                severity="CRITICAL",
            )
        )

        # GCP credentials
        credentials.append(
            ExtractedCredential(
                source="terraform",
                credential_type="gcp_service_account_key",
                location=f"{file_location}#provider.google.credentials",
                severity="CRITICAL",
            )
        )

        # Azure credentials
        credentials.append(
            ExtractedCredential(
                source="terraform",
                credential_type="azure_client_secret",
                location=f"{file_location}#provider.azurerm.client_secret",
                severity="CRITICAL",
            )
        )

        return credentials

    def detect_vault(self) -> VaultProfile:
        """Detect HashiCorp Vault installation.

        Returns:
            VaultProfile with installation details
        """
        profile = VaultProfile(installed=False)

        # In real impl: kubectl get pod -n vault vault-0
        profile.installed = True
        profile.version = "1.15.0"
        profile.namespace = "vault"
        profile.auth_method = "kubernetes"
        profile.is_unsealed = True
        profile.kv_paths_accessible = ["kv/", "secret/"]

        return profile

    def enumerate_vault_secrets(self, _token: str = "hvs.mock") -> list[str]:
        """Enumerate paths in Vault KV store.

        Args:
            _token: Vault auth token

        Returns:
            List of secret paths
        """
        paths = [
            "kv/production/database",
            "kv/production/api-keys",
            "kv/staging/credentials",
            "secret/aws/prod-access-key",
            "secret/azure/subscription-creds",
            "secret/gcp/service-account.json",
        ]
        return paths

    def extract_vault_secrets(self, token: str = "hvs.mock") -> list[ExtractedCredential]:
        """Extract secrets from Vault.

        Args:
            token: Vault auth token

        Returns:
            List of extracted secrets
        """
        secrets = []

        paths = self.enumerate_vault_secrets(token)

        for path in paths:
            secrets.append(
                ExtractedCredential(
                    source="vault",
                    credential_type="secret",
                    location=f"vault://{path}",
                    severity="CRITICAL",
                )
            )

        return secrets

    def extract_kubeconfig_from_etcd(self) -> ExtractedCredential:
        """Extract kubeconfig from etcd.

        Returns:
            Extracted kubeconfig credential
        """
        return ExtractedCredential(
            source="etcd",
            credential_type="kubeconfig",
            location="etcd://registry/secrets/kube-system/admin-kubeconfig",
            severity="CRITICAL",
        )

    def extract_service_account_tokens_from_etcd(self) -> list[ExtractedCredential]:
        """Extract service account tokens from etcd.

        Returns:
            List of extracted SA tokens
        """
        tokens = []

        # Default SA token
        tokens.append(
            ExtractedCredential(
                source="etcd",
                credential_type="service_account_token",
                location="etcd://registry/secrets/default/default-token",
                severity="HIGH",
            )
        )

        # System SA tokens
        for sa in ["kubernetes-dashboard", "prometheus", "ingress-nginx"]:
            tokens.append(
                ExtractedCredential(
                    source="etcd",
                    credential_type="service_account_token",
                    location=f"etcd://registry/secrets/kube-system/{sa}-token",
                    severity="CRITICAL",
                )
            )

        return tokens

    def generate_secret_extraction_commands(self) -> list[str]:
        """Generate commands to extract secrets.

        Returns:
            List of extraction commands
        """
        commands = [
            "# Terraform state files in S3",
            "aws s3 ls s3://*/terraform.tfstate --recursive",
            "aws s3 cp s3://company-tfstate/prod/terraform.tfstate . && jq '.resources[].instances[].attributes' terraform.tfstate",
            "",
            "# Vault secrets enumeration",
            "vault kv list kv/",
            "vault kv get -format=json kv/production/database",
            "",
            "# etcd secret extraction",
            "etcdctl get /registry/secrets --prefix | jq",
            "etcdctl get /registry/secrets/kube-system/admin-kubeconfig",
        ]
        return commands
