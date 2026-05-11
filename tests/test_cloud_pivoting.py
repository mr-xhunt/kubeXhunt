"""Tests for cloud credential pivoting."""

import pytest

from kubexhunt.exploit.cloud_pivoting import (
    CloudCredential,
    CloudPivotingEngine,
    CloudProvider,
    CloudResource,
    IdentityBinding,
    IMDSEndpoint,
)


class TestIMDSEndpoint:
    """Test IMDS endpoint configuration."""

    def test_aws_imds_endpoint(self):
        """Test AWS IMDS endpoint configuration."""
        endpoint = IMDSEndpoint(
            provider=CloudProvider.AWS,
            endpoint_url="http://169.254.169.254/latest",
            requires_token=True,
            token_header="X-aws-ec2-metadata-token-ttl-seconds",
        )

        assert endpoint.provider == CloudProvider.AWS
        assert endpoint.requires_token is True
        assert "169.254.169.254" in endpoint.endpoint_url

    def test_gcp_imds_endpoint(self):
        """Test GCP metadata service endpoint."""
        endpoint = IMDSEndpoint(
            provider=CloudProvider.GCP,
            endpoint_url="http://metadata.google.internal/computeMetadata/v1",
            requires_token=False,
            token_header="Metadata-Flavor",
        )

        assert endpoint.provider == CloudProvider.GCP
        assert endpoint.requires_token is False

    def test_endpoint_serialization(self):
        """Test serializing endpoint to dict."""
        endpoint = IMDSEndpoint(
            provider=CloudProvider.AWS,
            endpoint_url="http://169.254.169.254/latest",
            requires_token=True,
        )

        endpoint_dict = endpoint.to_dict()

        assert endpoint_dict["provider"] == "aws"
        assert endpoint_dict["requires_token"] is True


class TestCloudCredential:
    """Test cloud credential object."""

    def test_aws_credential_creation(self):
        """Test creating AWS credential."""
        cred = CloudCredential(
            provider=CloudProvider.AWS,
            credential_type="role_credentials",
            access_key="AKIA...",
            secret_key="***SECRET***",
            role_name="eks-pod-role",
        )

        assert cred.provider == CloudProvider.AWS
        assert cred.credential_type == "role_credentials"

    def test_credential_redaction(self):
        """Test that secrets are redacted in serialization."""
        cred = CloudCredential(
            provider=CloudProvider.AWS,
            credential_type="role_credentials",
            access_key="AKIA1234567890ABCDEF",
            secret_key="very-secret-key",
            session_token="very-long-session-token",
        )

        cred_dict = cred.to_dict()

        assert "***REDACTED***" in str(cred_dict["secret_key"])
        assert "***REDACTED***" in str(cred_dict["session_token"])
        assert "AKIA123" in cred_dict["access_key"]

    def test_gcp_credential_creation(self):
        """Test creating GCP credential."""
        cred = CloudCredential(
            provider=CloudProvider.GCP,
            credential_type="service_account_token",
            token="very-long-jwt-token",
            scope=["cloud-platform"],
        )

        assert cred.provider == CloudProvider.GCP
        assert len(cred.scope) > 0


class TestCloudResource:
    """Test cloud resource object."""

    def test_s3_bucket_resource(self):
        """Test creating S3 bucket resource."""
        resource = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="bucket",
            resource_name="prod-backups",
            region="us-east-1",
            access_level="read",
            sensitive_data=True,
        )

        assert resource.provider == CloudProvider.AWS
        assert resource.resource_type == "bucket"
        assert resource.sensitive_data is True

    def test_database_resource(self):
        """Test creating database resource."""
        resource = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="rds_database",
            resource_name="prod-db",
            region="us-west-2",
            access_level="write",
            sensitive_data=True,
        )

        assert resource.resource_type == "rds_database"
        assert resource.access_level == "write"

    def test_resource_serialization(self):
        """Test serializing resource to dict."""
        resource = CloudResource(
            provider=CloudProvider.AWS,
            resource_type="bucket",
            resource_name="prod-data",
            sensitive_data=True,
        )

        resource_dict = resource.to_dict()

        assert resource_dict["provider"] == "aws"
        assert resource_dict["sensitive_data"] is True


class TestCloudPivotingEngine:
    """Test cloud pivoting orchestration."""

    def test_engine_initialization(self):
        """Test initializing the engine."""
        engine = CloudPivotingEngine()

        assert engine.detected_providers == []
        assert engine.retrieved_credentials == {}

    def test_aws_imds_endpoint_configured(self):
        """Test AWS IMDS endpoint is properly configured."""
        engine = CloudPivotingEngine()

        aws_endpoint = engine.IMDS_ENDPOINTS[CloudProvider.AWS]

        assert aws_endpoint.provider == CloudProvider.AWS
        assert aws_endpoint.requires_token is True

    def test_gcp_imds_endpoint_configured(self):
        """Test GCP metadata endpoint is properly configured."""
        engine = CloudPivotingEngine()

        gcp_endpoint = engine.IMDS_ENDPOINTS[CloudProvider.GCP]

        assert gcp_endpoint.provider == CloudProvider.GCP

    def test_retrieve_aws_credentials(self):
        """Test AWS credential retrieval (mocked)."""
        engine = CloudPivotingEngine()

        cred = engine.retrieve_aws_credentials()

        assert cred.provider == CloudProvider.AWS
        assert cred.credential_type == "role_credentials"

    def test_retrieve_gcp_credentials(self):
        """Test GCP credential retrieval (mocked)."""
        engine = CloudPivotingEngine()

        cred = engine.retrieve_gcp_credentials()

        assert cred.provider == CloudProvider.GCP
        assert cred.credential_type == "service_account_token"

    def test_retrieve_azure_credentials(self):
        """Test Azure credential retrieval (mocked)."""
        engine = CloudPivotingEngine()

        cred = engine.retrieve_azure_credentials()

        assert cred.provider == CloudProvider.AZURE
        assert cred.credential_type == "managed_identity_token"

    def test_generate_aws_lateral_movement_commands(self):
        """Test generating AWS lateral movement commands."""
        engine = CloudPivotingEngine()
        cred = CloudCredential(
            provider=CloudProvider.AWS,
            credential_type="role_credentials",
        )

        commands = engine.generate_cloud_lateral_movement_commands(CloudProvider.AWS, cred)

        assert len(commands) > 0
        assert any("aws s3" in cmd for cmd in commands)
        assert any("aws rds" in cmd for cmd in commands)
        assert any("aws ec2" in cmd for cmd in commands)

    def test_generate_gcp_lateral_movement_commands(self):
        """Test generating GCP lateral movement commands."""
        engine = CloudPivotingEngine()
        cred = CloudCredential(
            provider=CloudProvider.GCP,
            credential_type="service_account_token",
        )

        commands = engine.generate_cloud_lateral_movement_commands(CloudProvider.GCP, cred)

        assert len(commands) > 0
        assert any("gcloud" in cmd for cmd in commands)

    def test_generate_azure_lateral_movement_commands(self):
        """Test generating Azure lateral movement commands."""
        engine = CloudPivotingEngine()
        cred = CloudCredential(
            provider=CloudProvider.AZURE,
            credential_type="managed_identity_token",
        )

        commands = engine.generate_cloud_lateral_movement_commands(CloudProvider.AZURE, cred)

        assert len(commands) > 0
        assert any("az " in cmd for cmd in commands)

    def test_engine_serialization(self):
        """Test serializing engine state to dict."""
        engine = CloudPivotingEngine()
        engine.detected_providers = [CloudProvider.AWS, CloudProvider.GCP]

        engine_dict = engine.to_dict()

        assert "aws" in engine_dict["detected_providers"]
        assert "gcp" in engine_dict["detected_providers"]

    @pytest.mark.parametrize(
        "provider,expected_endpoint",
        [
            (CloudProvider.AWS, "169.254.169.254"),
            (CloudProvider.GCP, "metadata.google.internal"),
            (CloudProvider.AZURE, "169.254.169.254"),
        ],
    )
    def test_imds_endpoints_configured(self, provider, expected_endpoint):
        """Test IMDS endpoints are properly configured."""
        engine = CloudPivotingEngine()
        endpoint = engine.IMDS_ENDPOINTS[provider]

        assert expected_endpoint in endpoint.endpoint_url


class TestIdentityBindings:
    """Test Kubernetes to cloud identity binding mechanisms."""

    def test_aws_irsa_enum(self):
        """Test AWS IRSA enum."""
        assert IdentityBinding.AWS_IRSA.value == "aws-irsa"

    def test_gcp_workload_identity_enum(self):
        """Test GCP Workload Identity enum."""
        assert IdentityBinding.GCP_WI.value == "gcp-workload-identity"

    def test_azure_pod_identity_enum(self):
        """Test Azure Pod Identity enum."""
        assert IdentityBinding.AZURE_POD_MI.value == "azure-pod-identity"

    def test_azure_oidc_federation_enum(self):
        """Test Azure OIDC Federation enum."""
        assert IdentityBinding.AZURE_OIDC.value == "azure-oidc-federation"
