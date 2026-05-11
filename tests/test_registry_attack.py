"""Tests for container registry attack detection and exploitation."""

import pytest

from kubexhunt.core.graph import RelationType
from kubexhunt.supply_chain.registry_attack import (
    RegistryAttacker,
    RegistryCredential,
    VulnerableImage,
)


@pytest.fixture
def registry_attacker():
    """Create RegistryAttacker instance."""
    return RegistryAttacker()


class TestRegistryCredentialDataclass:
    """Test RegistryCredential dataclass."""

    def test_credential_serialization(self):
        """Test credential to_dict serialization."""
        cred = RegistryCredential(
            server="registry.example.com",
            username="admin",
            password_hint="***REDACTED***",
            auth_type="basic",
            namespaces_using=["default", "kube-system"],
            is_writable=True,
        )
        d = cred.to_dict()
        assert d["server"] == "registry.example.com"
        assert d["username"] == "admin"
        assert d["is_writable"] is True
        assert len(d["namespaces_using"]) == 2

    def test_credential_default_values(self):
        """Test RegistryCredential default field values."""
        cred = RegistryCredential(
            server="docker.io",
            username="user",
        )
        assert cred.auth_type == "basic"
        assert cred.is_writable is False
        assert cred.namespaces_using == []


class TestVulnerableImageDataclass:
    """Test VulnerableImage dataclass."""

    def test_image_serialization(self):
        """Test image to_dict serialization."""
        img = VulnerableImage(
            image="app-service",
            tag="latest",
            registry="azurecr.io/company",
            mutable_tag=True,
            unsigned=True,
            public_registry=False,
            used_by_pods=["app-pod-1", "app-pod-2"],
        )
        d = img.to_dict()
        assert d["image"] == "app-service"
        assert d["mutable_tag"] is True
        assert len(d["used_by_pods"]) == 2

    def test_image_risk_level_calculation(self):
        """Test image risk level based on mutability and signature."""
        # Mutable and unsigned = highest risk
        img = VulnerableImage(
            image="risky",
            tag="latest",
            registry="public",
            mutable_tag=True,
            unsigned=True,
        )
        assert img.mutable_tag and img.unsigned


class TestEnumerateRegistryCredentials:
    """Test registry credential enumeration."""

    def test_enumerate_finds_credentials(self, registry_attacker):
        """Test enumerate_registry_credentials returns credentials."""
        creds = registry_attacker.enumerate_registry_credentials()
        assert len(creds) > 0
        assert all(isinstance(c, RegistryCredential) for c in creds)

    def test_credentials_have_required_fields(self, registry_attacker):
        """Test all credentials have required fields."""
        creds = registry_attacker.enumerate_registry_credentials()
        for cred in creds:
            assert cred.server
            assert cred.username
            assert isinstance(cred.is_writable, bool)

    def test_writable_registries_identified(self, registry_attacker):
        """Test at least some registries are writable."""
        creds = registry_attacker.enumerate_registry_credentials()
        writable = [c for c in creds if c.is_writable]
        assert len(writable) > 0

    def test_credential_namespaces_populated(self, registry_attacker):
        """Test credentials list namespaces where they're used."""
        creds = registry_attacker.enumerate_registry_credentials()
        has_namespaces = any(c.namespaces_using for c in creds)
        assert has_namespaces


class TestFindVulnerableImages:
    """Test vulnerable image discovery."""

    def test_find_vulnerable_images(self, registry_attacker):
        """Test find_vulnerable_images returns images."""
        images = registry_attacker.find_vulnerable_images()
        assert len(images) > 0
        assert all(isinstance(img, VulnerableImage) for img in images)

    def test_images_have_required_fields(self, registry_attacker):
        """Test all images have required fields."""
        images = registry_attacker.find_vulnerable_images()
        for img in images:
            assert img.image
            assert img.tag
            assert img.registry

    def test_mutable_tags_identified(self, registry_attacker):
        """Test mutable tags like 'latest' are identified."""
        images = registry_attacker.find_vulnerable_images()
        mutable = [img for img in images if img.mutable_tag]
        assert len(mutable) > 0

    def test_unsigned_images_identified(self, registry_attacker):
        """Test unsigned images are identified."""
        images = registry_attacker.find_vulnerable_images()
        unsigned = [img for img in images if img.unsigned]
        assert len(unsigned) > 0

    def test_image_usage_tracked(self, registry_attacker):
        """Test pod usage is tracked for images."""
        images = registry_attacker.find_vulnerable_images()
        used_images = [img for img in images if img.used_by_pods]
        assert len(used_images) > 0


class TestImagePoisoningChain:
    """Test image poisoning exploit chain generation."""

    def test_generate_image_poisoning_chain(self, registry_attacker):
        """Test image poisoning chain generation."""
        images = registry_attacker.find_vulnerable_images()
        chain = registry_attacker.generate_image_poisoning_chain(images[0])
        assert chain is not None
        assert chain.path_id
        assert len(chain.steps) > 0
        assert len(chain.nodes) > 0

    def test_poisoning_chain_structure(self, registry_attacker):
        """Test poisoning chain has proper structure."""
        images = registry_attacker.find_vulnerable_images()
        chain = registry_attacker.generate_image_poisoning_chain(images[0])
        assert chain.title
        assert chain.description
        assert chain.complexity in ["TRIVIAL", "EASY", "MEDIUM", "HARD"]

    def test_poisoning_chain_has_executable_commands(self, registry_attacker):
        """Test poisoning chain steps have executable commands."""
        images = registry_attacker.find_vulnerable_images()
        chain = registry_attacker.generate_image_poisoning_chain(images[0])
        for step in chain.steps:
            assert step.command
            assert len(step.command.strip()) > 0

    def test_poisoning_chain_uses_correct_relation(self, registry_attacker):
        """Test poisoning chain uses POISONS_IMAGE relation."""
        images = registry_attacker.find_vulnerable_images()
        chain = registry_attacker.generate_image_poisoning_chain(images[0])
        for step in chain.steps:
            assert step.relation == RelationType.POISONS_IMAGE


class TestCredentialTheftCommands:
    """Test credential theft command generation."""

    def test_generate_credential_theft_commands(self, registry_attacker):
        """Test credential theft command generation."""
        commands = registry_attacker.generate_credential_theft_commands()
        assert len(commands) > 0
        assert all(isinstance(cmd, str) for cmd in commands)

    def test_commands_contain_extraction_methods(self, registry_attacker):
        """Test commands include various extraction methods."""
        commands = registry_attacker.generate_credential_theft_commands()
        # Should have multiple command patterns
        kubectl_cmds = [c for c in commands if "kubectl" in c]
        assert len(kubectl_cmds) > 0

    def test_commands_extract_docker_config(self, registry_attacker):
        """Test commands extract docker config."""
        commands = registry_attacker.generate_credential_theft_commands()
        config_cmds = [c for c in commands if "dockerconfigjson" in c or ".dockercfg" in c]
        assert len(config_cmds) > 0


class TestMITREMappings:
    """Test MITRE ATT&CK technique mappings."""

    def test_poisoning_chain_has_mitre_techniques(self, registry_attacker):
        """Test poisoning chain maps MITRE techniques."""
        images = registry_attacker.find_vulnerable_images()
        chain = registry_attacker.generate_image_poisoning_chain(images[0])
        for step in chain.steps:
            assert step.mitre_techniques
            assert all(isinstance(t, str) for t in step.mitre_techniques)
            assert all(t.startswith("T") for t in step.mitre_techniques)


class TestRegistryAttackerIntegration:
    """Integration tests for registry attacker."""

    def test_full_attack_flow(self, registry_attacker):
        """Test complete attack flow from discovery to exploitation."""
        # Discover credentials
        creds = registry_attacker.enumerate_registry_credentials()
        assert len(creds) > 0

        # Find vulnerable images
        images = registry_attacker.find_vulnerable_images()
        assert len(images) > 0

        # Generate exploitation chain
        chain = registry_attacker.generate_image_poisoning_chain(images[0])
        assert chain is not None

        # Generate credential theft commands
        commands = registry_attacker.generate_credential_theft_commands()
        assert len(commands) > 0

    def test_attack_targeting_writable_registries(self, registry_attacker):
        """Test attack focuses on writable registries."""
        creds = registry_attacker.enumerate_registry_credentials()
        writable = [c for c in creds if c.is_writable]
        assert len(writable) > 0
        for cred in writable:
            assert cred.server
