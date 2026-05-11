"""Tests for workload identity abuse."""

from kubexhunt.advanced.workload_identity import (
    AzureWIBinding,
    GCPWIBinding,
    IRSABinding,
    WorkloadIdentityAbuser,
)


class TestIRSABinding:
    """Test AWS IRSA binding."""

    def test_irsa_binding_creation(self):
        """Test creating IRSA binding."""
        binding = IRSABinding(
            service_account="app-sa",
            namespace="production",
            iam_role_arn="arn:aws:iam::123456789012:role/app-role",
            iam_role_name="app-role",
            iam_role_policies=["S3FullAccess"],
            is_overprivileged=True,
        )

        assert binding.service_account == "app-sa"
        assert binding.namespace == "production"
        assert binding.is_overprivileged is True

    def test_irsa_binding_serialization(self):
        """Test IRSA binding serialization."""
        binding = IRSABinding(
            service_account="test-sa",
            namespace="default",
            iam_role_arn="arn:aws:iam::111111111111:role/test-role",
            iam_role_name="test-role",
            iam_role_policies=["ReadOnlyAccess"],
        )

        binding_dict = binding.to_dict()

        assert binding_dict["service_account"] == "test-sa"
        assert binding_dict["iam_role_name"] == "test-role"
        assert len(binding_dict["iam_role_policies"]) == 1

    def test_irsa_binding_default_token_path(self):
        """Test IRSA binding has default token path."""
        binding = IRSABinding(
            service_account="sa",
            namespace="ns",
            iam_role_arn="arn:aws:iam::111111111111:role/r",
            iam_role_name="r",
        )

        assert "/var/run/secrets/eks.amazonaws.com" in binding.token_projection_path


class TestGCPWIBinding:
    """Test GCP Workload Identity binding."""

    def test_gcp_wi_binding_creation(self):
        """Test creating GCP WI binding."""
        binding = GCPWIBinding(
            kubernetes_sa="kube-sa",
            kubernetes_namespace="kube-ns",
            gcp_service_account="sa@project.iam.gserviceaccount.com",
            gcp_project="my-project",
            gcp_roles=["roles/editor"],
        )

        assert binding.kubernetes_sa == "kube-sa"
        assert binding.gcp_service_account == "sa@project.iam.gserviceaccount.com"

    def test_gcp_wi_binding_serialization(self):
        """Test GCP WI binding serialization."""
        binding = GCPWIBinding(
            kubernetes_sa="test-sa",
            kubernetes_namespace="default",
            gcp_service_account="test@project.iam.gserviceaccount.com",
            gcp_project="project-id",
            gcp_roles=["roles/viewer"],
        )

        binding_dict = binding.to_dict()

        assert binding_dict["kubernetes_sa"] == "test-sa"
        assert binding_dict["gcp_project"] == "project-id"


class TestAzureWIBinding:
    """Test Azure workload identity binding."""

    def test_azure_wi_binding_creation(self):
        """Test creating Azure WI binding."""
        binding = AzureWIBinding(
            kubernetes_sa="azure-sa",
            kubernetes_namespace="default",
            azure_client_id="client-id",
            azure_tenant_id="tenant-id",
            azure_subscription_id="sub-id",
            federation_issuer="https://kubernetes.default.svc.cluster.local",
            federation_subject="system:serviceaccount:default:azure-sa",
            roles=["Owner"],
        )

        assert binding.kubernetes_sa == "azure-sa"
        assert binding.azure_client_id == "client-id"
        assert "Owner" in binding.roles

    def test_azure_wi_binding_serialization(self):
        """Test Azure WI binding serialization."""
        binding = AzureWIBinding(
            kubernetes_sa="test-sa",
            kubernetes_namespace="ns",
            azure_client_id="client",
            azure_tenant_id="tenant",
            azure_subscription_id="sub",
            federation_issuer="issuer",
            federation_subject="subject",
        )

        binding_dict = binding.to_dict()

        assert binding_dict["kubernetes_sa"] == "test-sa"
        assert binding_dict["binding_type"] == "federated"


class TestEnumerateIRSABindings:
    """Test IRSA binding enumeration."""

    def test_enumerate_irsa_bindings(self):
        """Test enumerating IRSA bindings."""
        abuser = WorkloadIdentityAbuser()
        bindings = abuser.enumerate_irsa_bindings()

        assert len(bindings) >= 1
        assert all(isinstance(b, IRSABinding) for b in bindings)

    def test_irsa_bindings_have_arns(self):
        """Test that IRSA bindings include ARNs."""
        abuser = WorkloadIdentityAbuser()
        bindings = abuser.enumerate_irsa_bindings()

        for binding in bindings:
            assert "arn:aws:iam" in binding.iam_role_arn


class TestEnumerateGCPWIBindings:
    """Test GCP WI binding enumeration."""

    def test_enumerate_gcp_wi_bindings(self):
        """Test enumerating GCP WI bindings."""
        abuser = WorkloadIdentityAbuser()
        bindings = abuser.enumerate_gcp_wi_bindings()

        assert len(bindings) >= 1
        assert all(isinstance(b, GCPWIBinding) for b in bindings)

    def test_gcp_wi_bindings_have_project(self):
        """Test that GCP WI bindings include project."""
        abuser = WorkloadIdentityAbuser()
        bindings = abuser.enumerate_gcp_wi_bindings()

        for binding in bindings:
            assert binding.gcp_project


class TestEnumerateAzureWIBindings:
    """Test Azure WI binding enumeration."""

    def test_enumerate_azure_wi_bindings(self):
        """Test enumerating Azure WI bindings."""
        abuser = WorkloadIdentityAbuser()
        bindings = abuser.enumerate_azure_wi_bindings()

        assert len(bindings) >= 1
        assert all(isinstance(b, AzureWIBinding) for b in bindings)

    def test_azure_wi_bindings_have_client_id(self):
        """Test that Azure WI bindings include client ID."""
        abuser = WorkloadIdentityAbuser()
        bindings = abuser.enumerate_azure_wi_bindings()

        for binding in bindings:
            assert binding.azure_client_id


class TestFindOverprivilegedBindings:
    """Test finding overprivileged bindings."""

    def test_find_overprivileged_bindings(self):
        """Test finding overprivileged bindings."""
        abuser = WorkloadIdentityAbuser()
        overprivileged = abuser.find_overprivileged_bindings()

        assert isinstance(overprivileged, list)
        # Each element should be a tuple (binding_id, severity)
        assert all(isinstance(item, tuple) and len(item) == 2 for item in overprivileged)

    def test_overprivileged_bindings_have_severity(self):
        """Test that overprivileged bindings include severity."""
        abuser = WorkloadIdentityAbuser()
        overprivileged = abuser.find_overprivileged_bindings()

        for _binding_id, severity in overprivileged:
            assert severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestGenerateIRSAAbuse:
    """Test IRSA abuse chain generation."""

    def test_generate_irsa_abuse_chain(self):
        """Test generating IRSA abuse chain."""
        binding = IRSABinding(
            service_account="app-sa",
            namespace="production",
            iam_role_arn="arn:aws:iam::123456789012:role/app-role",
            iam_role_name="app-role",
            iam_role_policies=["S3FullAccess"],
        )

        abuser = WorkloadIdentityAbuser()
        chain = abuser.generate_irsa_abuse_chain(binding)

        assert chain.path_id is not None
        assert len(chain.steps) >= 2
        assert all(hasattr(step, "command") for step in chain.steps)

    def test_irsa_abuse_chain_has_sts(self):
        """Test IRSA abuse chain includes STS call."""
        binding = IRSABinding(
            service_account="sa",
            namespace="ns",
            iam_role_arn="arn:aws:iam::111111111111:role/role",
            iam_role_name="role",
        )

        abuser = WorkloadIdentityAbuser()
        chain = abuser.generate_irsa_abuse_chain(binding)
        script = chain.to_bash_script()

        assert "sts:AssumeRoleWithWebIdentity" in script or "assume-role" in script


class TestGenerateGCPWIAbuse:
    """Test GCP WI abuse chain generation."""

    def test_generate_gcp_wi_abuse_chain(self):
        """Test generating GCP WI abuse chain."""
        binding = GCPWIBinding(
            kubernetes_sa="kube-sa",
            kubernetes_namespace="default",
            gcp_service_account="sa@project.iam.gserviceaccount.com",
            gcp_project="project",
            gcp_roles=["roles/editor"],
        )

        abuser = WorkloadIdentityAbuser()
        chain = abuser.generate_gcp_wi_abuse_chain(binding)

        assert chain.path_id is not None
        assert len(chain.steps) >= 1


class TestGenerateCrossAccountChains:
    """Test cross-account AWS escalation chains."""

    def test_generate_cross_account_chains(self):
        """Test generating cross-account chains."""
        binding = IRSABinding(
            service_account="sa",
            namespace="ns",
            iam_role_arn="arn:aws:iam::111111111111:role/role",
            iam_role_name="role",
            iam_role_policies=["AssumeRoleFullAccess"],
        )

        abuser = WorkloadIdentityAbuser()
        chains = abuser.generate_cross_account_chains([binding])

        assert isinstance(chains, list)

    def test_cross_account_chain_structure(self):
        """Test cross-account chain has proper structure."""
        binding = IRSABinding(
            service_account="sa",
            namespace="ns",
            iam_role_arn="arn:aws:iam::111111111111:role/role",
            iam_role_name="role",
            iam_role_policies=["sts:AssumeRole"],
        )

        abuser = WorkloadIdentityAbuser()
        chains = abuser.generate_cross_account_chains([binding])

        if len(chains) > 0:
            chain = chains[0]
            assert len(chain.steps) >= 1
