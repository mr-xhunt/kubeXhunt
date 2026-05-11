"""Supply chain attack vectors: container registries and CI/CD pipelines.

Detect and exploit vulnerabilities in software delivery pipelines:
- Container registries (credential theft, image poisoning, mutable tags)
- CI/CD tools (ArgoCD, Flux, Jenkins, GitHub Actions secret extraction)
- Helm chart analysis for RBAC escalation

Modules:
    registry_attack: Container registry credential theft and image poisoning
    cicd_attack: ArgoCD, Flux, Jenkins, GitHub Actions compromise
"""

from kubexhunt.supply_chain.cicd_attack import (
    ArgoCDProfile,
    CICDAttacker,
    FluxProfile,
    PipelineSecret,
)
from kubexhunt.supply_chain.registry_attack import (
    RegistryAttacker,
    RegistryCredential,
    VulnerableImage,
)

__all__ = [
    "RegistryCredential",
    "VulnerableImage",
    "RegistryAttacker",
    "ArgoCDProfile",
    "FluxProfile",
    "PipelineSecret",
    "CICDAttacker",
]
