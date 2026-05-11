"""Normalized findings, evidence, and graph models.

This module defines the core data structures for KubeXHunt findings and attack path analysis.
Structured to support MITRE ATT&CK v13, CWE, CVSS 3.1, and Kubernetes-specific risk scoring.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class Severity(str, Enum):
    """CVSS 3.1-aligned severity levels."""

    CRITICAL = "CRITICAL"  # CVSS 9.0–10.0
    HIGH = "HIGH"  # CVSS 7.0–8.9
    MEDIUM = "MEDIUM"  # CVSS 4.0–6.9
    LOW = "LOW"  # CVSS 0.1–3.9
    INFO = "INFO"  # Informational


class Confidence(float):
    """Confidence level as a float 0.0–1.0."""

    def __new__(cls, value: float):
        if not 0.0 <= value <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")
        return float(value)


@dataclass
class Evidence:
    """Atomic supporting evidence for a finding or graph edge."""

    kind: str
    source: str
    value: str
    timestamp: str | None = None


@dataclass
class RemediationStep:
    """A single remediation step with effort estimation."""

    step: str
    effort: Literal["TRIVIAL", "LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    commands: list[str] = field(default_factory=list)  # kubectl, AWS CLI, etc.
    config_diff: str | None = None  # YAML or JSON diff


@dataclass
class Remediation:
    """Structured remediation guidance."""

    summary: str
    steps: list[RemediationStep] = field(default_factory=list)
    estimated_effort_minutes: int = 30
    references: list[str] = field(default_factory=list)


@dataclass
class AttackPathChain:
    """A concrete attack path that chains this finding to cluster compromise."""

    path_id: str
    nodes: list[str]  # e.g., ["sa:default:app", "pod:default:nginx", "node:*", "CLUSTER_ADMIN"]
    steps: list[str]  # Human-readable steps
    exploitability: Literal["TRIVIAL", "LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    requires_interaction: bool = False


@dataclass
class Finding:
    """Normalized finding model for modular engines and reports.

    Attributes:
        id: Stable, unique finding ID (e.g., "RBAC-WILDCARD-001")
        title: Short, actionable title
        severity: CVSS 3.1-aligned (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        confidence: 0.0–1.0 probability the finding is accurate
        category: Kubernetes-specific category (Privilege Escalation, Lateral Movement, etc.)
        phase: Which KubeXHunt phase discovered this
        observed: True if actively confirmed; False if inferred
        description: Technical explanation of the risk
        remediation: Structured remediation guidance
        evidence: Supporting observations
        resource: The K8s resource affected (kind, name, namespace, etc.)
        tags: Arbitrary categorization tags
        mitre: MITRE ATT&CK for Containers technique IDs (e.g., "T1078.001")
        cwe: CWE IDs (e.g., "CWE-276")
        cis: CIS Kubernetes Benchmark control IDs
        nist: NIST CSF framework IDs
        references: External documentation and PoCs
        engine: Which engine/module produced this finding
        attack_paths: Concrete chains from this finding to cluster compromise
        opsec_rating: How easily this finding would be detected by logging/monitoring
    """

    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.8
    category: str = ""
    phase: str = ""
    observed: bool = True
    description: str = ""
    remediation: Remediation | None = None

    evidence: list[Evidence] = field(default_factory=list)
    resource: dict[str, str] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    mitre: list[str] = field(default_factory=list)  # e.g., ["T1078.001", "T1087.002"]
    cwe: list[str] = field(default_factory=list)  # e.g., ["CWE-276"]
    cis: list[str] = field(default_factory=list)  # e.g., ["5.1.1"]
    nist: list[str] = field(default_factory=list)  # e.g., ["AC-2", "AC-6"]
    references: list[str] = field(default_factory=list)

    engine: str = ""
    attack_paths: list[AttackPathChain] = field(default_factory=list)
    opsec_rating: Literal["SILENT", "QUIET", "MEDIUM", "LOUD"] = "MEDIUM"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "category": self.category,
            "phase": self.phase,
            "observed": self.observed,
            "description": self.description,
            "remediation": {
                "summary": self.remediation.summary,
                "steps": [
                    {
                        "step": s.step,
                        "effort": s.effort,
                        "commands": s.commands,
                        "config_diff": s.config_diff,
                    }
                    for s in (self.remediation.steps if self.remediation else [])
                ],
                "estimated_effort_minutes": self.remediation.estimated_effort_minutes if self.remediation else 30,
            }
            if self.remediation
            else None,
            "evidence": [
                {
                    "kind": e.kind,
                    "source": e.source,
                    "value": e.value,
                    "timestamp": e.timestamp,
                }
                for e in self.evidence
            ],
            "resource": self.resource,
            "tags": self.tags,
            "mitre": self.mitre,
            "cwe": self.cwe,
            "cis": self.cis,
            "nist": self.nist,
            "references": self.references,
            "engine": self.engine,
            "attack_paths": [
                {
                    "path_id": p.path_id,
                    "nodes": p.nodes,
                    "steps": p.steps,
                    "exploitability": p.exploitability,
                    "requires_interaction": p.requires_interaction,
                }
                for p in self.attack_paths
            ],
            "opsec_rating": self.opsec_rating,
        }
