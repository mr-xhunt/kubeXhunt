"""Defense evasion techniques and runtime security detection.

Detect defensive tooling (Falco, Tetragon, AppArmor, Seccomp) in the cluster
and generate evasion techniques for each defense mechanism.

Modules:
    runtime_detector: Detect defensive tools and characterize coverage gaps
    evasion_generator: Generate evasion techniques per detected defense
"""

from kubexhunt.evasion.evasion_generator import (
    EvasionGenerator,
    EvasionTechnique,
)
from kubexhunt.evasion.runtime_detector import (
    AppArmorProfile,
    CoverageReport,
    FalcoProfile,
    RuntimeDefense,
    RuntimeDetector,
    SeccompProfile,
    TetragonProfile,
)

__all__ = [
    "RuntimeDefense",
    "FalcoProfile",
    "TetragonProfile",
    "AppArmorProfile",
    "SeccompProfile",
    "CoverageReport",
    "RuntimeDetector",
    "EvasionTechnique",
    "EvasionGenerator",
]
