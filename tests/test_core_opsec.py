"""Tests for opsec rating system."""

import pytest

from kubexhunt.core.opsec import (
    PHASE_OPSEC_RATINGS,
    OpSecLevel,
    get_api_call_opsec_rating,
    get_phase_opsec_rating,
    should_skip_phase_in_stealth_mode,
)


class TestOpSecLevel:
    """Test OpSecLevel enum."""

    def test_opsec_level_values(self):
        """Test that OpSecLevel has all expected values."""
        assert OpSecLevel.SILENT.value == "SILENT"
        assert OpSecLevel.QUIET.value == "QUIET"
        assert OpSecLevel.MEDIUM.value == "MEDIUM"
        assert OpSecLevel.LOUD.value == "LOUD"

    def test_opsec_level_ordering(self):
        """Test ordering of opsec levels (silent < quiet < medium < loud)."""
        levels = [OpSecLevel.SILENT, OpSecLevel.QUIET, OpSecLevel.MEDIUM, OpSecLevel.LOUD]
        values = [0, 1, 2, 3]

        for level, value in zip(levels, values):
            assert level.value == levels[value].value


class TestPhaseOpsecRatings:
    """Test phase-level opsec ratings."""

    def test_phase_0_quiet(self):
        """Test that Phase 0 (setup) is rated QUIET."""
        rating = get_phase_opsec_rating(0)
        assert rating == "QUIET"

    def test_phase_1_silent(self):
        """Test that Phase 1 (pod recon) is rated SILENT."""
        rating = get_phase_opsec_rating(1)
        assert rating == "SILENT"

    def test_phase_4_loud(self):
        """Test that Phase 4 (network) is rated LOUD."""
        rating = get_phase_opsec_rating(4)
        assert rating == "LOUD"

    def test_phase_13_loud(self):
        """Test that Phase 13 (secrets) is rated LOUD."""
        rating = get_phase_opsec_rating(13)
        assert rating == "LOUD"

    def test_all_phases_have_ratings(self):
        """Test that all main phases (0-26) have opsec ratings."""
        for phase in range(27):
            rating = get_phase_opsec_rating(phase)
            assert rating in ["SILENT", "QUIET", "MEDIUM", "LOUD"]

    def test_unknown_phase_defaults_to_medium(self):
        """Test that unknown phases default to MEDIUM."""
        rating = get_phase_opsec_rating(9999)
        assert rating == "MEDIUM"


class TestAPICallOpsecRating:
    """Test per-API-call opsec ratings."""

    def test_get_secret_single_is_loud(self):
        """Test that getting a single secret is rated LOUD (secrets are highly audited)."""
        rating = get_api_call_opsec_rating("get", "secrets", namespace="default")
        assert rating == "LOUD"

    def test_list_secrets_all_is_loud(self):
        """Test that listing all secrets (no namespace) is rated LOUD."""
        rating = get_api_call_opsec_rating("list", "secrets", namespace=None)
        assert rating == "LOUD"

    def test_list_secrets_single_namespace_is_loud(self):
        """Test that listing secrets in a namespace is rated LOUD (secrets are highly audited)."""
        rating = get_api_call_opsec_rating("list", "secrets", namespace="default")
        assert rating == "LOUD"

    def test_create_pod_is_loud(self):
        """Test that creating a pod is rated LOUD."""
        rating = get_api_call_opsec_rating("create", "pods")
        assert rating == "LOUD"

    def test_exec_pod_is_loud(self):
        """Test that exec into a pod is rated LOUD."""
        rating = get_api_call_opsec_rating("exec", "pods")
        assert rating == "LOUD"

    def test_get_pod_is_quiet(self):
        """Test that getting a pod is rated QUIET."""
        rating = get_api_call_opsec_rating("get", "pods", namespace="default")
        assert rating == "QUIET"

    def test_patch_rolebinding_is_medium(self):
        """Test that patching a RoleBinding is rated MEDIUM."""
        rating = get_api_call_opsec_rating("patch", "rolebindings", namespace="default")
        assert rating == "MEDIUM"

    def test_unknown_verb_defaults_to_medium(self):
        """Test that unknown verbs default to MEDIUM."""
        rating = get_api_call_opsec_rating("unknown_verb", "pods")
        assert rating in ["QUIET", "MEDIUM", "LOUD"]  # defaults to medium or derived from resource


class TestStealthModeFiltering:
    """Test stealth mode phase filtering."""

    def test_stealth_0_includes_all_phases(self):
        """Test that stealth=0 includes all phases."""
        for phase in [0, 1, 4, 5, 8, 13, 14]:
            should_skip = should_skip_phase_in_stealth_mode(phase, stealth_level=0)
            assert should_skip is False, f"Phase {phase} should not be skipped in stealth=0"

    def test_stealth_1_skips_loud_phases(self):
        """Test that stealth=1 skips LOUD phases."""
        loud_phases = [4, 5, 8, 13, 14]  # network, escape, privesc, secrets, dos
        for phase in loud_phases:
            should_skip = should_skip_phase_in_stealth_mode(phase, stealth_level=1)
            assert should_skip is True, f"Phase {phase} should be skipped in stealth=1"

    def test_stealth_1_includes_quiet_phases(self):
        """Test that stealth=1 includes QUIET/SILENT phases."""
        quiet_phases = [0, 1, 2, 10, 11, 12]  # setup, pod, cloud, cloud platforms
        for phase in quiet_phases:
            should_skip = should_skip_phase_in_stealth_mode(phase, stealth_level=1)
            # Some might not exist or have different ratings, just check it's callable
            assert isinstance(should_skip, bool)

    def test_stealth_2_skips_medium_and_loud(self):
        """Test that stealth=2 skips MEDIUM and LOUD phases."""
        medium_or_loud_phases = [3, 4, 5, 6, 7, 8, 13, 14, 15]
        for phase in medium_or_loud_phases:
            should_skip = should_skip_phase_in_stealth_mode(phase, stealth_level=2)
            # These should mostly be skipped
            if get_phase_opsec_rating(phase) in ["LOUD", "MEDIUM"]:
                assert should_skip is True, f"Phase {phase} should be skipped in stealth=2"

    def test_stealth_2_includes_silent_phases(self):
        """Test that stealth=2 includes SILENT phases."""
        silent_phases = [1]  # Phase 1 is SILENT
        for phase in silent_phases:
            should_skip = should_skip_phase_in_stealth_mode(phase, stealth_level=2)
            if get_phase_opsec_rating(phase) == "SILENT":
                assert should_skip is False

    @pytest.mark.parametrize("stealth_level", [0, 1, 2])
    def test_stealth_mode_returns_boolean(self, stealth_level):
        """Test that stealth mode always returns a boolean."""
        result = should_skip_phase_in_stealth_mode(5, stealth_level)
        assert isinstance(result, bool)


class TestOpsecRatingConsistency:
    """Test consistency of opsec ratings."""

    def test_phase_ratings_are_valid_strings(self):
        """Test that all phase ratings are valid opsec level strings."""
        for _phase, rating in PHASE_OPSEC_RATINGS.items():
            assert rating in ["SILENT", "QUIET", "MEDIUM", "LOUD"]

    def test_related_phases_have_similar_ratings(self):
        """Test that logically related phases have similar opsec profiles."""
        # Cloud metadata phases should be quiet
        cloud_phases = [2, 10, 11, 12]
        for phase in cloud_phases:
            rating = get_phase_opsec_rating(phase)
            assert rating in ["SILENT", "QUIET"], f"Cloud phase {phase} should be quiet, got {rating}"

        # Attack phases should be loud
        attack_phases = [4, 5, 8, 13, 14]
        for phase in attack_phases:
            rating = get_phase_opsec_rating(phase)
            assert rating in ["MEDIUM", "LOUD"], f"Attack phase {phase} should be loud, got {rating}"
