"""
Tests for Feature 6 — Version Intelligence Engine
"""

from __future__ import annotations

import pytest

from aasm.modules.version_intel.engine import (
    VersionIntelligenceEngine,
    VersionInfo,
    PLATFORM_VERSION_DB,
    _is_outdated,
    _parse_semver,
)
from aasm.modules.version_intel.advisories import (
    KNOWN_ADVISORIES,
    SecurityAdvisory,
    get_advisories_for_platform,
)
from aasm.core.models import AIService, AIServiceType, AuthType


def make_service(platform: str, version: str) -> AIService:
    return AIService(
        host="127.0.0.1",
        port=8080,
        url=f"http://127.0.0.1:8080",
        service_type=AIServiceType.LOCAL_LLM,
        platform=platform,
        version=version,
        auth_required=False,
        auth_type=AuthType.NONE,
    )


class TestParseSemver:
    def test_parse_simple_version(self):
        assert _parse_semver("1.2.3") == (1, 2, 3)

    def test_parse_version_with_v_prefix(self):
        assert _parse_semver("v0.3.14") == (0, 3, 14)

    def test_parse_two_part_version(self):
        result = _parse_semver("1.2")
        assert result[0] == 1 and result[1] == 2

    def test_parse_prerelease_version(self):
        result = _parse_semver("0.3.14-beta1")
        assert result == (0, 3, 14)

    def test_parse_invalid_returns_none(self):
        assert _parse_semver("unknown") is None

    def test_parse_empty_returns_none(self):
        assert _parse_semver("") is None


class TestIsOutdated:
    def test_older_version_is_outdated(self):
        assert _is_outdated("0.1.0", "0.3.14") is True

    def test_same_version_not_outdated(self):
        assert _is_outdated("0.3.14", "0.3.14") is False

    def test_newer_version_not_outdated(self):
        assert _is_outdated("0.4.0", "0.3.14") is False

    def test_major_version_difference(self):
        assert _is_outdated("1.0.0", "2.0.0") is True

    def test_unknown_version_not_outdated(self):
        assert _is_outdated("unknown", "1.0.0") is False


class TestSecurityAdvisories:
    def test_known_advisories_not_empty(self):
        assert len(KNOWN_ADVISORIES) > 0

    def test_advisories_have_required_fields(self):
        for adv in KNOWN_ADVISORIES:
            assert adv.advisory_id
            assert adv.platform
            assert adv.title
            assert adv.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_get_advisories_for_ollama(self):
        advisories = get_advisories_for_platform("Ollama")
        assert len(advisories) > 0
        assert all(a.platform == "Ollama" for a in advisories)

    def test_get_advisories_case_insensitive(self):
        advisories = get_advisories_for_platform("ollama")
        assert len(advisories) > 0

    def test_get_advisories_unknown_platform_returns_empty(self):
        advisories = get_advisories_for_platform("UnknownPlatformXYZ")
        assert advisories == []

    def test_flowise_has_advisories(self):
        advisories = get_advisories_for_platform("Flowise")
        assert len(advisories) > 0

    def test_litellm_has_advisories(self):
        advisories = get_advisories_for_platform("LiteLLM")
        assert len(advisories) > 0


class TestVersionIntelligenceEngine:
    def test_enrich_known_platform_outdated(self):
        engine = VersionIntelligenceEngine()
        service = make_service("Ollama", "0.1.0")
        vi = engine.enrich(service)

        assert vi is not None
        assert vi.platform == "Ollama"
        assert vi.is_outdated is True
        assert vi.latest_stable is not None

    def test_enrich_known_platform_current(self):
        engine = VersionIntelligenceEngine()
        latest = PLATFORM_VERSION_DB["Ollama"]["latest_stable"]
        service = make_service("Ollama", latest)
        vi = engine.enrich(service)

        assert vi is not None
        assert vi.is_outdated is False

    def test_enrich_unknown_version(self):
        engine = VersionIntelligenceEngine()
        service = make_service("Ollama", "unknown")
        vi = engine.enrich(service)

        assert vi is not None
        assert vi.detected_version == "unknown"
        assert vi.confidence == 0.5

    def test_enrich_stores_metadata(self):
        engine = VersionIntelligenceEngine()
        service = make_service("LiteLLM", "1.0.0")
        vi = engine.enrich(service)

        assert "version_intel" in service.metadata
        meta = service.metadata["version_intel"]
        assert "detected_version" in meta
        assert "is_outdated" in meta
        assert "advisory_count" in meta

    def test_enrich_adds_outdated_tag(self):
        engine = VersionIntelligenceEngine()
        service = make_service("Ollama", "0.1.0")
        engine.enrich(service)
        assert "outdated-version" in service.tags

    def test_enrich_adds_critical_advisory_tag(self):
        engine = VersionIntelligenceEngine()
        service = make_service("Flowise", "1.0.0")
        engine.enrich(service)
        if any(a.severity == "CRITICAL" for a in get_advisories_for_platform("Flowise")):
            assert "critical-advisories" in service.tags

    def test_enrich_returns_none_for_unknown_platform(self):
        engine = VersionIntelligenceEngine()
        service = make_service("", "1.0.0")
        vi = engine.enrich(service)
        assert vi is None

    def test_version_label_outdated(self):
        vi = VersionInfo(
            platform="Ollama",
            detected_version="0.1.0",
            is_outdated=True,
        )
        assert vi.version_label == "OUTDATED"

    def test_version_label_unknown(self):
        vi = VersionInfo(
            platform="Ollama",
            detected_version="unknown",
        )
        assert vi.version_label == "UNKNOWN"

    def test_version_label_eol(self):
        vi = VersionInfo(
            platform="Ollama",
            detected_version="0.0.1",
            eol=True,
        )
        assert vi.version_label == "END-OF-LIFE"

    def test_advisory_count(self):
        adv = SecurityAdvisory(
            advisory_id="TEST-001",
            platform="Test",
            affected_versions=["<1.0.0"],
            fixed_version="1.0.0",
            severity="HIGH",
            title="Test Advisory",
            description="Test",
        )
        vi = VersionInfo(
            platform="Test",
            detected_version="0.5.0",
            advisories=[adv],
        )
        assert vi.advisory_count == 1
        assert not vi.has_critical_advisories

    def test_version_matches_range_less_than(self):
        engine = VersionIntelligenceEngine()
        assert engine._version_matches_range("0.1.0", "<1.0.0") is True
        assert engine._version_matches_range("1.0.0", "<1.0.0") is False
        assert engine._version_matches_range("1.5.0", "<1.0.0") is False

    def test_enrich_many(self):
        engine = VersionIntelligenceEngine()
        services = [
            make_service("Ollama", "0.1.0"),
            make_service("LiteLLM", "1.0.0"),
        ]
        results = engine.enrich_many(services)
        assert len(results) == 2
        assert all(isinstance(r, VersionInfo) for r in results)

    def test_all_platforms_in_db(self):
        expected_platforms = {
            "Ollama", "Open WebUI", "LiteLLM", "vLLM", "Flowise",
            "Dify", "Langflow", "AnythingLLM", "LocalAI",
        }
        for p in expected_platforms:
            assert p in PLATFORM_VERSION_DB, f"{p} not in PLATFORM_VERSION_DB"
