"""Tests for evasion technique generation."""

from kubexhunt.evasion.evasion_generator import (
    EvasionGenerator,
    EvasionReliability,
    EvasionTechnique,
)
from kubexhunt.evasion.runtime_detector import (
    AppArmorProfile,
    FalcoProfile,
    RuntimeDefense,
    SeccompProfile,
    TetragonProfile,
)


class TestEvasionTechnique:
    """Test EvasionTechnique dataclass."""

    def test_evasion_technique_creation(self):
        """Test creating an evasion technique."""
        tech = EvasionTechnique(
            technique_id="EVD-001",
            target_defense=RuntimeDefense.FALCO,
            description="Bypass Falco via nsenter",
            command="nsenter -t $(pgrep bash) -m /bin/bash",
            detection_risk="QUIET",
            mitre_techniques=["T1562.001"],
            reliability=EvasionReliability.HIGH,
        )

        assert tech.technique_id == "EVD-001"
        assert tech.target_defense == RuntimeDefense.FALCO
        assert tech.reliability == EvasionReliability.HIGH

    def test_evasion_technique_serialization(self):
        """Test evasion technique serialization."""
        tech = EvasionTechnique(
            technique_id="EVD-002",
            target_defense=RuntimeDefense.TETRAGON,
            description="Bypass Tetragon",
            command="cat /sys/kernel/debug/tracing/events",
            detection_risk="SILENT",
            mitre_techniques=["T1087"],
            reliability=EvasionReliability.MEDIUM,
        )

        tech_dict = tech.to_dict()

        assert tech_dict["technique_id"] == "EVD-002"
        assert tech_dict["target_defense"] == "tetragon"
        assert tech_dict["reliability"] == "MEDIUM"


class TestFalcoBypassGeneration:
    """Test Falco evasion bypass generation."""

    def test_generate_falco_bypasses(self):
        """Test generating Falco bypasses."""
        generator = EvasionGenerator()
        profile = FalcoProfile(
            installed=True,
            enabled=True,
            rules_count=128,
            monitored_syscalls=["execve", "open"],
        )

        techniques = generator.generate_falco_bypasses(profile)

        assert len(techniques) >= 2
        assert all(t.target_defense == RuntimeDefense.FALCO for t in techniques)

    def test_falco_nsenter_technique(self):
        """Test nsenter bypass technique."""
        generator = EvasionGenerator()
        profile = FalcoProfile(installed=True, enabled=True)

        techniques = generator.generate_falco_bypasses(profile)
        nsenter_tech = next((t for t in techniques if "nsenter" in t.command), None)

        assert nsenter_tech is not None
        assert nsenter_tech.technique_id == "EVD-001"
        assert nsenter_tech.reliability == EvasionReliability.HIGH

    def test_falco_disabled_no_bypasses(self):
        """Test that disabled Falco generates no bypasses."""
        generator = EvasionGenerator()
        profile = FalcoProfile(installed=True, enabled=False)

        techniques = generator.generate_falco_bypasses(profile)

        assert len(techniques) == 0


class TestTetragonBypassGeneration:
    """Test Tetragon evasion bypass generation."""

    def test_generate_tetragon_bypasses(self):
        """Test generating Tetragon bypasses."""
        generator = EvasionGenerator()
        profile = TetragonProfile(
            installed=True,
            enabled=True,
            tracing_policies=5,
        )

        techniques = generator.generate_tetragon_bypasses(profile)

        assert len(techniques) >= 1
        assert all(t.target_defense == RuntimeDefense.TETRAGON for t in techniques)

    def test_tetragon_not_installed(self):
        """Test Tetragon not installed returns empty."""
        generator = EvasionGenerator()
        profile = TetragonProfile(installed=False)

        techniques = generator.generate_tetragon_bypasses(profile)

        assert len(techniques) == 0


class TestAppArmorBypassGeneration:
    """Test AppArmor evasion bypass generation."""

    def test_generate_apparmor_bypasses(self):
        """Test generating AppArmor bypasses."""
        generator = EvasionGenerator()
        profile = AppArmorProfile(
            installed=True,
            mode="enforce",
            enabled_profiles=3,
        )

        techniques = generator.generate_apparmor_bypasses(profile)

        assert len(techniques) >= 1

    def test_apparmor_unenforced_no_bypasses(self):
        """Test that unenforced AppArmor generates no bypasses."""
        generator = EvasionGenerator()
        profile = AppArmorProfile(installed=True, mode="complain")

        techniques = generator.generate_apparmor_bypasses(profile)

        assert len(techniques) == 0


class TestSeccompBypassGeneration:
    """Test Seccomp evasion bypass generation."""

    def test_generate_seccomp_bypasses(self):
        """Test generating Seccomp bypasses."""
        generator = EvasionGenerator()
        profile = SeccompProfile(
            installed=True,
            default_policy="audit",
            blocked_syscalls=["ptrace", "mount"],
        )

        techniques = generator.generate_seccomp_bypasses(profile)

        assert len(techniques) >= 1

    def test_seccomp_not_installed_no_bypasses(self):
        """Test that Seccomp not installed generates no bypasses."""
        generator = EvasionGenerator()
        profile = SeccompProfile(installed=False)

        techniques = generator.generate_seccomp_bypasses(profile)

        assert len(techniques) == 0


class TestPSSBypassGeneration:
    """Test Pod Security Standards bypass generation."""

    def test_generate_pss_bypasses(self):
        """Test generating PSS bypasses."""
        generator = EvasionGenerator()

        techniques = generator.generate_pss_bypasses()

        assert len(techniques) >= 2
        # PSS bypasses should include debug (ephemeral) and privileged tricks
        assert any("debug" in t.command.lower() or "privileged" in t.command.lower() for t in techniques)

    def test_pss_bypass_includes_mitre(self):
        """Test PSS bypasses include MITRE techniques."""
        generator = EvasionGenerator()

        techniques = generator.generate_pss_bypasses()

        assert all(len(t.mitre_techniques) > 0 for t in techniques)


class TestBashScriptGeneration:
    """Test bash script generation from evasion techniques."""

    def test_to_bash_script_single_technique(self):
        """Test generating bash script for single technique."""
        tech = EvasionTechnique(
            technique_id="EVD-001",
            target_defense=RuntimeDefense.FALCO,
            description="Test bypass",
            command="echo 'test'",
            detection_risk="QUIET",
            mitre_techniques=["T1562.001"],
        )

        generator = EvasionGenerator()
        script = generator.to_bash_script([tech])

        assert "#!/bin/bash" in script
        assert "EVD-001" in script
        assert "echo 'test'" in script
        assert "T1562.001" in script

    def test_to_bash_script_multiple_techniques(self):
        """Test generating bash script for multiple techniques."""
        techs = [
            EvasionTechnique(
                technique_id="EVD-001",
                target_defense=RuntimeDefense.FALCO,
                description="Bypass 1",
                command="cmd1",
                detection_risk="QUIET",
                mitre_techniques=["T1562.001"],
            ),
            EvasionTechnique(
                technique_id="EVD-002",
                target_defense=RuntimeDefense.TETRAGON,
                description="Bypass 2",
                command="cmd2",
                detection_risk="SILENT",
                mitre_techniques=["T1087"],
            ),
        ]

        generator = EvasionGenerator()
        script = generator.to_bash_script(techs)

        assert "EVD-001" in script
        assert "EVD-002" in script
        assert "cmd1" in script
        assert "cmd2" in script
        assert script.count("#!/bin/bash") == 1


class TestGenerateAllBypasses:
    """Test generating all bypasses at once."""

    def test_generate_all_bypasses(self):
        """Test generating bypasses for all defenses."""
        generator = EvasionGenerator()
        falco = FalcoProfile(installed=True, enabled=True)
        tetragon = TetragonProfile(installed=True, enabled=True)
        apparmor = AppArmorProfile(installed=True, mode="enforce")
        seccomp = SeccompProfile(installed=True)

        techniques = generator.generate_all_bypasses(
            falco=falco,
            tetragon=tetragon,
            apparmor=apparmor,
            seccomp=seccomp,
        )

        assert len(techniques) >= 10
        assert any(t.target_defense == RuntimeDefense.FALCO for t in techniques)
        assert any(t.target_defense == RuntimeDefense.TETRAGON for t in techniques)
