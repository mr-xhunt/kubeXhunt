"""Tests for core data models (Finding, Evidence, etc.)."""

import pytest

from kubexhunt.core.models import (
    AttackPathChain,
    Evidence,
    Finding,
    Remediation,
    RemediationStep,
    Severity,
)


class TestEvidence:
    """Test Evidence data class."""

    def test_evidence_creation(self):
        """Test creating an Evidence instance."""
        evidence = Evidence(
            kind="ClusterRole.rules",
            source="API /apis/rbac.authorization.k8s.io/v1/clusterroles/admin",
            value="{ apiGroups: ['*'], resources: ['secrets'], verbs: ['*'] }",
            timestamp="2026-05-11T10:00:00Z",
        )

        assert evidence.kind == "ClusterRole.rules"
        assert evidence.source.startswith("API")
        assert evidence.timestamp == "2026-05-11T10:00:00Z"

    def test_evidence_without_timestamp(self):
        """Test Evidence without explicit timestamp."""
        evidence = Evidence(
            kind="Pod.spec",
            source="enumeration",
            value="hostPath: /host",
        )

        assert evidence.timestamp is None


class TestRemediationStep:
    """Test RemediationStep data class."""

    def test_remediation_step_creation(self):
        """Test creating a RemediationStep."""
        step = RemediationStep(
            step="Restrict ClusterRole to specific verbs",
            effort="MEDIUM",
            commands=["kubectl patch clusterrole admin -p '{...}'"],
        )

        assert step.step == "Restrict ClusterRole to specific verbs"
        assert step.effort == "MEDIUM"
        assert len(step.commands) == 1


class TestRemediation:
    """Test Remediation data class."""

    def test_remediation_with_steps(self):
        """Test Remediation with multiple steps."""
        remediation = Remediation(
            summary="Fix overly permissive RBAC",
            steps=[
                RemediationStep(step="Step 1", effort="LOW"),
                RemediationStep(step="Step 2", effort="MEDIUM"),
            ],
            estimated_effort_minutes=45,
        )

        assert remediation.summary == "Fix overly permissive RBAC"
        assert len(remediation.steps) == 2
        assert remediation.estimated_effort_minutes == 45


class TestAttackPathChain:
    """Test AttackPathChain data class."""

    def test_attack_path_creation(self):
        """Test creating an attack path chain."""
        path = AttackPathChain(
            path_id="PATH-001",
            nodes=["sa:default:app", "clusterrole:admin", "secret:kube-system:token", "CLUSTER_ADMIN"],
            steps=[
                "Use SA to enumerate ClusterRoles",
                "Find admin role with wildcard permissions",
                "Use role to read all secrets",
                "Extract cluster-admin token",
            ],
            exploitability="HIGH",
        )

        assert path.path_id == "PATH-001"
        assert len(path.nodes) == 4
        assert len(path.steps) == 4
        assert path.exploitability == "HIGH"


class TestFinding:
    """Test Finding data class."""

    def test_finding_creation_minimal(self):
        """Test creating a Finding with minimal attributes."""
        finding = Finding(
            id="RBAC-001",
            title="Overly permissive ClusterRole",
            severity=Severity.CRITICAL,
            confidence=0.95,
            category="Privilege Escalation",
            phase="Phase 3",
            observed=True,
            description="The admin ClusterRole grants wildcard permissions.",
        )

        assert finding.id == "RBAC-001"
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == 0.95
        assert len(finding.evidence) == 0
        assert len(finding.mitre) == 0

    def test_finding_creation_complete(self):
        """Test creating a Finding with all attributes."""
        finding = Finding(
            id="RBAC-WILDCARD-001",
            title="ClusterRole with overly permissive wildcard verbs",
            severity=Severity.CRITICAL,
            confidence=0.95,
            category="Privilege Escalation",
            phase="Phase 3 (RBAC Analysis)",
            observed=True,
            description="ClusterRole 'viewer' grants '*' verbs on secrets.",
            remediation=Remediation(
                summary="Restrict ClusterRole permissions",
                steps=[
                    RemediationStep(
                        step="Patch the ClusterRole",
                        effort="LOW",
                        commands=["kubectl patch clusterrole viewer -p '{...}'"],
                    ),
                ],
                estimated_effort_minutes=30,
            ),
            evidence=[
                Evidence(
                    kind="ClusterRole.rules",
                    source="API",
                    value="{ apiGroups: ['*'], resources: ['secrets'], verbs: ['*'] }",
                ),
            ],
            resource={"kind": "ClusterRole", "name": "viewer"},
            tags=["kubernetes", "rbac", "privilege-escalation"],
            mitre=["T1078.001", "T1087.002"],
            cwe=["CWE-276"],
            cis=["5.1.1"],
            nist=["AC-2", "AC-6"],
            references=["https://kubernetes.io/docs/reference/access-authn-authz/rbac/"],
            engine="rbac",
            attack_paths=[
                AttackPathChain(
                    path_id="PATH-001",
                    nodes=["sa:default:app", "clusterrole:viewer", "secret:kube-system:admin-token", "CLUSTER_ADMIN"],
                    steps=["Use SA to list secrets", "Extract admin token", "Create admin binding"],
                    exploitability="HIGH",
                ),
            ],
            opsec_rating="MEDIUM",
        )

        assert finding.id == "RBAC-WILDCARD-001"
        assert finding.severity == Severity.CRITICAL
        assert len(finding.evidence) == 1
        assert len(finding.mitre) == 2
        assert len(finding.attack_paths) == 1
        assert finding.opsec_rating == "MEDIUM"

    def test_finding_severity_enum(self):
        """Test Severity enum values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_finding_to_dict(self):
        """Test serializing a Finding to JSON-compatible dict."""
        finding = Finding(
            id="TEST-001",
            title="Test finding",
            severity=Severity.MEDIUM,
            confidence=0.8,
            category="Test",
            phase="Phase 1",
            observed=True,
            description="A test finding",
        )

        finding_dict = finding.to_dict()

        assert finding_dict["id"] == "TEST-001"
        assert finding_dict["severity"] == "MEDIUM"
        assert finding_dict["confidence"] == 0.8
        assert isinstance(finding_dict["evidence"], list)
        assert isinstance(finding_dict["mitre"], list)

    def test_finding_with_remediation_to_dict(self):
        """Test serializing a Finding with remediation to dict."""
        finding = Finding(
            id="TEST-002",
            title="Test with remediation",
            severity=Severity.HIGH,
            confidence=0.9,
            category="Test",
            phase="Phase 1",
            observed=True,
            description="Test",
            remediation=Remediation(
                summary="Fix the issue",
                steps=[
                    RemediationStep(step="First", effort="LOW"),
                ],
                estimated_effort_minutes=20,
            ),
        )

        finding_dict = finding.to_dict()

        assert finding_dict["remediation"] is not None
        assert finding_dict["remediation"]["summary"] == "Fix the issue"
        assert finding_dict["remediation"]["estimated_effort_minutes"] == 20

    @pytest.mark.parametrize(
        "severity,confidence",
        [
            (Severity.CRITICAL, 1.0),
            (Severity.HIGH, 0.95),
            (Severity.MEDIUM, 0.8),
            (Severity.LOW, 0.5),
            (Severity.INFO, 0.3),
        ],
    )
    def test_finding_severity_confidence_combinations(self, severity, confidence):
        """Test various severity and confidence combinations."""
        finding = Finding(
            id=f"TEST-{severity.value}",
            title=f"Test {severity.value}",
            severity=severity,
            confidence=confidence,
            category="Test",
            phase="Phase 1",
            observed=True,
            description="Test",
        )

        assert finding.severity == severity
        assert finding.confidence == confidence
        assert 0.0 <= finding.confidence <= 1.0
