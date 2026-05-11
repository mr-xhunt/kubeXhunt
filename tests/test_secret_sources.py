"""Tests for secret source extraction (Terraform, Vault, etcd)."""

import pytest

from kubexhunt.advanced.secret_sources import (
    ExtractedCredential,
    SecretSourceExtractor,
    TerraformStateFile,
    VaultProfile,
)


@pytest.fixture
def extractor():
    """Create SecretSourceExtractor instance."""
    return SecretSourceExtractor()


class TestTerraformStateFileDataclass:
    """Test TerraformStateFile dataclass."""

    def test_state_file_serialization(self):
        """Test TerraformStateFile to_dict serialization."""
        state = TerraformStateFile(
            location="s3://bucket/prod/terraform.tfstate",
            provider="aws",
            credentials_found=["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"],
            bucket="bucket",
            key="prod/terraform.tfstate",
            risk="CRITICAL",
        )
        d = state.to_dict()
        assert d["location"] == "s3://bucket/prod/terraform.tfstate"
        assert d["provider"] == "aws"
        assert len(d["credentials_found"]) == 2
        assert d["risk"] == "CRITICAL"

    def test_state_file_defaults(self):
        """Test TerraformStateFile default values."""
        state = TerraformStateFile(
            location="s3://bucket/state.tfstate",
            provider="aws",
        )
        assert state.credentials_found == []
        assert state.bucket == ""
        assert state.risk == "CRITICAL"


class TestVaultProfileDataclass:
    """Test VaultProfile dataclass."""

    def test_vault_profile_serialization(self):
        """Test VaultProfile to_dict serialization."""
        profile = VaultProfile(
            installed=True,
            version="1.15.0",
            namespace="vault",
            auth_method="kubernetes",
            is_unsealed=True,
            kv_paths_accessible=["kv/", "secret/"],
        )
        d = profile.to_dict()
        assert d["installed"] is True
        assert d["version"] == "1.15.0"
        assert d["is_unsealed"] is True
        assert len(d["kv_paths_accessible"]) == 2

    def test_vault_profile_defaults(self):
        """Test VaultProfile default values."""
        profile = VaultProfile(installed=False)
        assert profile.namespace == "vault"
        assert profile.auth_method == "kubernetes"
        assert profile.version is None


class TestExtractedCredentialDataclass:
    """Test ExtractedCredential dataclass."""

    def test_credential_serialization(self):
        """Test ExtractedCredential to_dict serialization."""
        cred = ExtractedCredential(
            source="terraform",
            credential_type="aws_access_key",
            value_hint="***REDACTED***",
            location="s3://bucket/terraform.tfstate#provider.aws.access_key",
            severity="CRITICAL",
        )
        d = cred.to_dict()
        assert d["source"] == "terraform"
        assert d["credential_type"] == "aws_access_key"
        assert d["value_hint"] == "***REDACTED***"
        assert d["severity"] == "CRITICAL"

    def test_credential_defaults(self):
        """Test ExtractedCredential default values."""
        cred = ExtractedCredential(
            source="vault",
            credential_type="database_password",
        )
        assert cred.value_hint == "***REDACTED***"
        assert cred.location == ""
        assert cred.severity == "CRITICAL"


class TestFindTerraformStateFiles:
    """Test Terraform state file discovery."""

    def test_find_terraform_state_files(self, extractor):
        """Test Terraform state file enumeration."""
        files = extractor.find_terraform_state_files()
        assert len(files) > 0
        assert all(isinstance(f, TerraformStateFile) for f in files)

    def test_state_files_have_required_fields(self, extractor):
        """Test state files have required fields."""
        files = extractor.find_terraform_state_files()
        for f in files:
            assert f.location
            assert f.provider
            assert f.risk

    def test_state_files_multiple_cloud_providers(self, extractor):
        """Test state files span multiple cloud providers."""
        files = extractor.find_terraform_state_files()
        providers = {f.provider for f in files}
        assert len(providers) >= 2  # At least AWS and GCP/Azure

    def test_state_files_have_credentials(self, extractor):
        """Test state files include discovered credentials."""
        files = extractor.find_terraform_state_files()
        with_creds = [f for f in files if f.credentials_found]
        assert len(with_creds) > 0

    def test_state_files_include_s3(self, extractor):
        """Test state files include S3 locations."""
        files = extractor.find_terraform_state_files()
        s3_files = [f for f in files if "s3://" in f.location]
        assert len(s3_files) > 0

    def test_state_files_include_gcs(self, extractor):
        """Test state files include GCS locations."""
        files = extractor.find_terraform_state_files()
        gcs_files = [f for f in files if "gs://" in f.location]
        assert len(gcs_files) > 0


class TestExtractTerraformCredentials:
    """Test credential extraction from Terraform state."""

    def test_extract_credentials_from_tfstate(self, extractor):
        """Test credential extraction."""
        creds = extractor.extract_credentials_from_tfstate("s3://bucket/terraform.tfstate")
        assert len(creds) > 0
        assert all(isinstance(c, ExtractedCredential) for c in creds)

    def test_extracted_credentials_have_fields(self, extractor):
        """Test extracted credentials have required fields."""
        creds = extractor.extract_credentials_from_tfstate("s3://bucket/terraform.tfstate")
        for cred in creds:
            assert cred.source == "terraform"
            assert cred.credential_type
            assert cred.location

    def test_extracted_credentials_aws(self, extractor):
        """Test AWS credentials extracted."""
        creds = extractor.extract_credentials_from_tfstate("s3://bucket/terraform.tfstate")
        aws_creds = [c for c in creds if "aws" in c.credential_type.lower()]
        assert len(aws_creds) > 0

    def test_extracted_credentials_gcp(self, extractor):
        """Test GCP credentials extracted."""
        creds = extractor.extract_credentials_from_tfstate("s3://bucket/terraform.tfstate")
        gcp_creds = [c for c in creds if "gcp" in c.credential_type.lower()]
        assert len(gcp_creds) > 0

    def test_extracted_credentials_azure(self, extractor):
        """Test Azure credentials extracted."""
        creds = extractor.extract_credentials_from_tfstate("s3://bucket/terraform.tfstate")
        azure_creds = [c for c in creds if "azure" in c.credential_type.lower()]
        assert len(azure_creds) > 0


class TestDetectVault:
    """Test Vault detection."""

    def test_detect_vault(self, extractor):
        """Test Vault detection."""
        profile = extractor.detect_vault()
        assert isinstance(profile, VaultProfile)
        assert hasattr(profile, "installed")

    def test_vault_profile_structure(self, extractor):
        """Test Vault profile structure."""
        profile = extractor.detect_vault()
        assert hasattr(profile, "version")
        assert hasattr(profile, "namespace")
        assert hasattr(profile, "auth_method")


class TestEnumerateVaultSecrets:
    """Test Vault secret path enumeration."""

    def test_enumerate_vault_secrets(self, extractor):
        """Test Vault secret enumeration."""
        paths = extractor.enumerate_vault_secrets()
        assert len(paths) > 0
        assert all(isinstance(p, str) for p in paths)

    def test_vault_paths_prefixed(self, extractor):
        """Test Vault paths are properly prefixed."""
        paths = extractor.enumerate_vault_secrets()
        # Paths should include mount prefixes like kv/ or secret/
        assert any("kv/" in p or "secret/" in p for p in paths)

    def test_vault_includes_database_secrets(self, extractor):
        """Test Vault includes database secrets."""
        paths = extractor.enumerate_vault_secrets()
        db_paths = [p for p in paths if "database" in p.lower()]
        assert len(db_paths) > 0

    def test_vault_includes_cloud_secrets(self, extractor):
        """Test Vault includes cloud provider secrets."""
        paths = extractor.enumerate_vault_secrets()
        cloud_paths = [p for p in paths if any(cloud in p.lower() for cloud in ["aws", "gcp", "azure"])]
        assert len(cloud_paths) > 0


class TestExtractVaultSecrets:
    """Test secret extraction from Vault."""

    def test_extract_vault_secrets(self, extractor):
        """Test Vault secret extraction."""
        secrets = extractor.extract_vault_secrets()
        assert len(secrets) > 0
        assert all(isinstance(s, ExtractedCredential) for s in secrets)

    def test_extracted_secrets_have_fields(self, extractor):
        """Test extracted secrets have required fields."""
        secrets = extractor.extract_vault_secrets()
        for secret in secrets:
            assert secret.source == "vault"
            assert secret.credential_type == "secret"
            assert "vault://" in secret.location

    def test_extracted_secrets_critical_severity(self, extractor):
        """Test extracted secrets marked critical."""
        secrets = extractor.extract_vault_secrets()
        assert all(s.severity == "CRITICAL" for s in secrets)


class TestExtractEtcdKubeconfig:
    """Test kubeconfig extraction from etcd."""

    def test_extract_kubeconfig_from_etcd(self, extractor):
        """Test kubeconfig extraction."""
        cred = extractor.extract_kubeconfig_from_etcd()
        assert isinstance(cred, ExtractedCredential)
        assert cred.source == "etcd"
        assert cred.credential_type == "kubeconfig"

    def test_kubeconfig_has_location(self, extractor):
        """Test kubeconfig has etcd location."""
        cred = extractor.extract_kubeconfig_from_etcd()
        assert "etcd://" in cred.location
        assert "kubeconfig" in cred.location.lower()

    def test_kubeconfig_critical_severity(self, extractor):
        """Test kubeconfig marked critical severity."""
        cred = extractor.extract_kubeconfig_from_etcd()
        assert cred.severity == "CRITICAL"


class TestExtractServiceAccountTokens:
    """Test service account token extraction from etcd."""

    def test_extract_service_account_tokens(self, extractor):
        """Test service account token extraction."""
        tokens = extractor.extract_service_account_tokens_from_etcd()
        assert len(tokens) > 0
        assert all(isinstance(t, ExtractedCredential) for t in tokens)

    def test_tokens_have_required_fields(self, extractor):
        """Test tokens have required fields."""
        tokens = extractor.extract_service_account_tokens_from_etcd()
        for token in tokens:
            assert token.source == "etcd"
            assert token.credential_type == "service_account_token"
            assert "etcd://" in token.location

    def test_tokens_include_default_sa(self, extractor):
        """Test tokens include default service account."""
        tokens = extractor.extract_service_account_tokens_from_etcd()
        default_tokens = [t for t in tokens if "default" in t.location.lower()]
        assert len(default_tokens) > 0

    def test_tokens_include_system_sa(self, extractor):
        """Test tokens include system service accounts."""
        tokens = extractor.extract_service_account_tokens_from_etcd()
        system_tokens = [t for t in tokens if "kube-system" in t.location.lower()]
        assert len(system_tokens) > 0


class TestGenerateSecretExtractionCommands:
    """Test secret extraction command generation."""

    def test_generate_extraction_commands(self, extractor):
        """Test command generation."""
        commands = extractor.generate_secret_extraction_commands()
        assert len(commands) > 0
        assert all(isinstance(c, str) for c in commands)

    def test_commands_include_terraform(self, extractor):
        """Test commands include Terraform state extraction."""
        commands = extractor.generate_secret_extraction_commands()
        tf_cmds = [c for c in commands if "terraform" in c.lower()]
        assert len(tf_cmds) > 0

    def test_commands_include_vault(self, extractor):
        """Test commands include Vault extraction."""
        commands = extractor.generate_secret_extraction_commands()
        vault_cmds = [c for c in commands if "vault" in c.lower()]
        assert len(vault_cmds) > 0

    def test_commands_include_etcd(self, extractor):
        """Test commands include etcd extraction."""
        commands = extractor.generate_secret_extraction_commands()
        etcd_cmds = [c for c in commands if "etcdctl" in c]
        assert len(etcd_cmds) > 0

    def test_commands_are_executable(self, extractor):
        """Test commands are executable patterns."""
        commands = extractor.generate_secret_extraction_commands()
        # Filter out comments
        executable = [c for c in commands if c and not c.startswith("#")]
        assert len(executable) > 0


class TestSecretSourceExtractorIntegration:
    """Integration tests for secret source extractor."""

    def test_full_secret_extraction_flow(self, extractor):
        """Test complete secret extraction flow."""
        # Find Terraform state files
        tf_files = extractor.find_terraform_state_files()
        assert len(tf_files) > 0

        # Extract Terraform credentials
        tf_creds = extractor.extract_credentials_from_tfstate(tf_files[0].location)
        assert len(tf_creds) > 0

        # Detect Vault
        vault = extractor.detect_vault()
        assert vault is not None

        # Extract Vault secrets
        vault_secrets = extractor.extract_vault_secrets()
        assert len(vault_secrets) > 0

        # Extract etcd secrets
        kubeconfig = extractor.extract_kubeconfig_from_etcd()
        sa_tokens = extractor.extract_service_account_tokens_from_etcd()
        assert kubeconfig is not None
        assert len(sa_tokens) > 0

    def test_all_credentials_marked_critical(self, extractor):
        """Test critical secrets identified."""
        tf_creds = extractor.extract_credentials_from_tfstate("s3://bucket/state.tfstate")
        vault_creds = extractor.extract_vault_secrets()
        kubeconfig = extractor.extract_kubeconfig_from_etcd()

        all_creds = tf_creds + vault_creds + [kubeconfig]
        critical_creds = [c for c in all_creds if c.severity == "CRITICAL"]
        assert len(critical_creds) > 0

    def test_extraction_commands_cover_all_sources(self, extractor):
        """Test commands cover all secret sources."""
        commands = extractor.generate_secret_extraction_commands()
        command_str = " ".join(commands).lower()

        # Should cover all sources
        assert "terraform" in command_str
        assert "vault" in command_str
        assert "etcd" in command_str
