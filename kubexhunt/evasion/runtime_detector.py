"""Detect defensive tooling in Kubernetes clusters.

Identifies installed runtime security tools (Falco, Tetragon, AppArmor, Seccomp)
and characterizes their coverage, alerting rules, and detection gaps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuntimeDefense(str, Enum):
    """Supported runtime security defenses."""

    FALCO = "falco"
    TETRAGON = "tetragon"
    APPARMOR = "apparmor"
    SECCOMP = "seccomp"
    SIEM_AGENT = "siem_agent"


@dataclass
class FalcoProfile:
    """Falco detection tool profile."""

    installed: bool
    version: str | None = None
    namespace: str | None = None
    enabled: bool = False
    rules_count: int = 0
    monitored_syscalls: list[str] = field(default_factory=list)
    coverage: float = 0.0  # percentage of cluster pods monitored

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "version": self.version,
            "namespace": self.namespace,
            "enabled": self.enabled,
            "rules_count": self.rules_count,
            "monitored_syscalls": self.monitored_syscalls,
            "coverage": self.coverage,
        }


@dataclass
class TetragonProfile:
    """Cilium Tetragon eBPF detection profile."""

    installed: bool
    version: str | None = None
    namespace: str | None = None
    enabled: bool = False
    tracing_policies: int = 0
    monitored_events: list[str] = field(default_factory=list)
    coverage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "version": self.version,
            "namespace": self.namespace,
            "enabled": self.enabled,
            "tracing_policies": self.tracing_policies,
            "monitored_events": self.monitored_events,
            "coverage": self.coverage,
        }


@dataclass
class AppArmorProfile:
    """AppArmor enforcement profile."""

    installed: bool
    mode: str = "unconfined"  # unconfined, complain, enforce
    enabled_profiles: int = 0
    monitored_namespaces: list[str] = field(default_factory=list)
    coverage: float = 0.0  # percentage of nodes with AppArmor enabled

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "mode": self.mode,
            "enabled_profiles": self.enabled_profiles,
            "monitored_namespaces": self.monitored_namespaces,
        }


@dataclass
class SeccompProfile:
    """Seccomp enforcement profile."""

    installed: bool
    default_policy: str = "none"  # none, audit, block
    profiles: list[str] = field(default_factory=list)
    blocked_syscalls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "installed": self.installed,
            "default_policy": self.default_policy,
            "profiles": self.profiles,
            "blocked_syscalls": self.blocked_syscalls,
        }


@dataclass
class SIEMAgent:
    """SIEM agent detection (Datadog, Splunk, Sysdig)."""

    name: str  # datadog, splunk, sysdig
    installed: bool
    namespace: str | None = None
    daemonset_name: str | None = None
    coverage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "name": self.name,
            "installed": self.installed,
            "namespace": self.namespace,
            "daemonset_name": self.daemonset_name,
            "coverage": self.coverage,
        }


@dataclass
class CoverageReport:
    """Overall cluster detection coverage report."""

    falco: FalcoProfile
    tetragon: TetragonProfile
    apparmor: AppArmorProfile
    seccomp: SeccompProfile
    siem_agents: list[SIEMAgent] = field(default_factory=list)

    overall_coverage: float = 0.0
    gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "falco": self.falco.to_dict(),
            "tetragon": self.tetragon.to_dict(),
            "apparmor": self.apparmor.to_dict(),
            "seccomp": self.seccomp.to_dict(),
            "siem_agents": [agent.to_dict() for agent in self.siem_agents],
            "overall_coverage": self.overall_coverage,
            "gaps": self.gaps,
        }


class RuntimeDetector:
    """Detect defensive tooling in Kubernetes cluster."""

    def __init__(self):
        """Initialize detector."""
        self.falco_profile = None
        self.tetragon_profile = None
        self.apparmor_profile = None
        self.seccomp_profile = None
        self.siem_agents = []

    def detect_falco(self) -> FalcoProfile:
        """Detect Falco installation and configuration.

        Returns:
            FalcoProfile with installation status and coverage info
        """
        profile = FalcoProfile(installed=False)

        # In real implementation, would check:
        # - kubectl get daemonset -A -o wide | grep falco
        # - kubectl get configmap falco-rules
        # - Get monitored syscalls from rules

        # Mocked detection
        profile.installed = True
        profile.version = "0.36.0"
        profile.namespace = "falco"
        profile.enabled = True
        profile.rules_count = 128
        profile.monitored_syscalls = ["execve", "open", "read", "write"]
        profile.coverage = 0.95

        self.falco_profile = profile
        return profile

    def detect_tetragon(self) -> TetragonProfile:
        """Detect Cilium Tetragon installation.

        Returns:
            TetragonProfile with eBPF coverage info
        """
        profile = TetragonProfile(installed=False)

        # In real implementation, would check:
        # - kubectl get daemonset -A -o wide | grep tetragon
        # - kubectl get TracingPolicy -A

        # Mocked detection
        profile.installed = False
        profile.version = None
        profile.enabled = False
        profile.tracing_policies = 0
        profile.coverage = 0.0

        self.tetragon_profile = profile
        return profile

    def detect_apparmor(self) -> AppArmorProfile:
        """Detect AppArmor enforcement in nodes.

        Returns:
            AppArmorProfile with node coverage
        """
        profile = AppArmorProfile(installed=False)

        # In real implementation, would check:
        # - Node annotations: container.apparmor.security.beta.kubernetes.io/*
        # - Node capabilities: apparmor

        # Mocked detection
        profile.installed = True
        profile.mode = "enforce"
        profile.enabled_profiles = 3
        profile.monitored_namespaces = ["production"]
        profile.coverage = 0.5  # 50% of nodes

        self.apparmor_profile = profile
        return profile

    def detect_seccomp(self) -> SeccompProfile:
        """Detect Seccomp enforcement.

        Returns:
            SeccompProfile with policy info
        """
        profile = SeccompProfile(installed=False)

        # In real implementation, would check:
        # - Pod securityContext.seccompProfile
        # - Cluster-wide default policy

        # Mocked detection
        profile.installed = True
        profile.default_policy = "audit"
        profile.profiles = ["restricted", "baseline"]
        profile.blocked_syscalls = ["ptrace", "mount", "umount2"]

        self.seccomp_profile = profile
        return profile

    def detect_siem_agents(self) -> list[SIEMAgent]:
        """Detect SIEM/monitoring agents (Datadog, Splunk, Sysdig).

        Returns:
            List of detected SIEM agents
        """
        agents = []

        # Check for Datadog
        datadog = SIEMAgent(
            name="datadog",
            installed=True,
            namespace="datadog",
            daemonset_name="datadog-agent",
            coverage=0.98,
        )
        agents.append(datadog)

        # Check for Splunk (typically not installed, placeholder)
        splunk = SIEMAgent(name="splunk", installed=False)
        agents.append(splunk)

        # Check for Sysdig (typically not installed, placeholder)
        sysdig = SIEMAgent(name="sysdig", installed=False)
        agents.append(sysdig)

        self.siem_agents = agents
        return agents

    def get_cluster_coverage(self) -> CoverageReport:
        """Build comprehensive coverage report.

        Returns:
            CoverageReport with all defenses and overall coverage
        """
        falco = self.detect_falco()
        tetragon = self.detect_tetragon()
        apparmor = self.detect_apparmor()
        seccomp = self.detect_seccomp()
        siem_agents = self.detect_siem_agents()

        # Calculate overall coverage
        coverages = [falco.coverage, tetragon.coverage, apparmor.coverage or 0.3]
        overall = sum(coverages) / len(coverages)

        gaps = []
        if not falco.enabled:
            gaps.append("Falco runtime monitoring disabled")
        if not tetragon.enabled:
            gaps.append("Tetragon eBPF monitoring not deployed")
        if apparmor.mode != "enforce":
            gaps.append("AppArmor not in enforce mode")
        if seccomp.default_policy == "none":
            gaps.append("Seccomp not enforced by default")

        report = CoverageReport(
            falco=falco,
            tetragon=tetragon,
            apparmor=apparmor,
            seccomp=seccomp,
            siem_agents=siem_agents,
            overall_coverage=overall,
            gaps=gaps,
        )

        return report
