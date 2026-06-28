"""
Feature 6 — Version Intelligence Engine
Goes beyond simple version detection: provides release status, age,
EOL status, latest stable version, and links to security advisories.
Enriches fingerprinting without changing existing scan logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from aasm.core.logger import get_logger
from aasm.core.models import AIService
from .advisories import SecurityAdvisory, get_advisories_for_platform

logger = get_logger("version_intel")


@dataclass
class VersionInfo:
    """Rich version intelligence for a detected AI platform."""
    platform: str
    detected_version: str
    latest_stable: str | None = None
    release_status: str = "unknown"
    is_outdated: bool = False
    release_age_days: int | None = None
    eol: bool = False
    eol_date: str | None = None
    advisories: list[SecurityAdvisory] = field(default_factory=list)
    confidence: float = 1.0

    @property
    def version_label(self) -> str:
        if self.eol:
            return "END-OF-LIFE"
        if self.is_outdated:
            return "OUTDATED"
        if self.detected_version in ("unknown", ""):
            return "UNKNOWN"
        return "UP-TO-DATE"

    @property
    def advisory_count(self) -> int:
        return len(self.advisories)

    @property
    def has_critical_advisories(self) -> bool:
        return any(a.severity == "CRITICAL" for a in self.advisories)


PLATFORM_VERSION_DB: dict[str, dict[str, Any]] = {
    "Ollama": {
        "latest_stable": "0.3.14",
        "release_status": "active",
        "eol": False,
    },
    "Open WebUI": {
        "latest_stable": "0.4.0",
        "release_status": "active",
        "eol": False,
    },
    "LiteLLM": {
        "latest_stable": "1.52.0",
        "release_status": "active",
        "eol": False,
    },
    "vLLM": {
        "latest_stable": "0.6.4",
        "release_status": "active",
        "eol": False,
    },
    "LM Studio": {
        "latest_stable": "0.3.5",
        "release_status": "active",
        "eol": False,
    },
    "Flowise": {
        "latest_stable": "2.1.4",
        "release_status": "active",
        "eol": False,
    },
    "Dify": {
        "latest_stable": "0.13.2",
        "release_status": "active",
        "eol": False,
    },
    "Langflow": {
        "latest_stable": "1.0.18",
        "release_status": "active",
        "eol": False,
    },
    "AnythingLLM": {
        "latest_stable": "1.7.3",
        "release_status": "active",
        "eol": False,
    },
    "LocalAI": {
        "latest_stable": "2.21.1",
        "release_status": "active",
        "eol": False,
    },
    "HuggingFace TGI": {
        "latest_stable": "2.4.0",
        "release_status": "active",
        "eol": False,
    },
    "OpenRouter": {
        "latest_stable": None,
        "release_status": "managed-service",
        "eol": False,
    },
    "CrewAI": {
        "latest_stable": "0.80.0",
        "release_status": "active",
        "eol": False,
    },
    "AutoGen": {
        "latest_stable": "0.4.0",
        "release_status": "active",
        "eol": False,
    },
    "LangGraph": {
        "latest_stable": "0.2.56",
        "release_status": "active",
        "eol": False,
    },
    "OpenHands": {
        "latest_stable": "0.14.0",
        "release_status": "active",
        "eol": False,
    },
    "FastChat": {
        "latest_stable": "0.2.36",
        "release_status": "active",
        "eol": False,
    },
    "Text Generation WebUI": {
        "latest_stable": "1.8.0",
        "release_status": "active",
        "eol": False,
    },
}


def _parse_semver(version: str) -> tuple[int, ...] | None:
    """Parse a semver-ish string to a tuple for comparison."""
    try:
        parts = version.lstrip("v").split(".")
        return tuple(int(p.split("-")[0]) for p in parts[:3])
    except Exception:
        return None


def _is_outdated(detected: str, latest: str) -> bool:
    """Return True if detected version is older than latest."""
    d = _parse_semver(detected)
    l_ = _parse_semver(latest)
    if d is None or l_ is None:
        return False
    return d < l_


class VersionIntelligenceEngine:
    """
    Enriches detected AI services with version intelligence:
    - latest stable version comparison
    - release status
    - age
    - EOL status
    - matching security advisories
    """

    def enrich(self, service: AIService) -> VersionInfo | None:
        """
        Produce a VersionInfo for the given service.
        Returns None if the platform is not in the version database.
        Stores results in service.metadata for downstream use.
        """
        platform = service.platform
        if not platform:
            return None

        db_entry = PLATFORM_VERSION_DB.get(platform)
        detected_version = service.version or "unknown"

        latest_stable = db_entry.get("latest_stable") if db_entry else None
        release_status = db_entry.get("release_status", "unknown") if db_entry else "unknown"
        eol = db_entry.get("eol", False) if db_entry else False
        eol_date = db_entry.get("eol_date") if db_entry else None

        is_outdated = False
        if latest_stable and detected_version not in ("unknown", ""):
            is_outdated = _is_outdated(detected_version, latest_stable)

        advisories = get_advisories_for_platform(platform)
        matched_advisories = self._match_advisories(detected_version, advisories)

        vi = VersionInfo(
            platform=platform,
            detected_version=detected_version,
            latest_stable=latest_stable,
            release_status=release_status,
            is_outdated=is_outdated,
            eol=eol,
            eol_date=eol_date,
            advisories=matched_advisories,
            confidence=0.9 if detected_version != "unknown" else 0.5,
        )

        service.metadata["version_intel"] = {
            "detected_version": vi.detected_version,
            "latest_stable": vi.latest_stable,
            "release_status": vi.release_status,
            "is_outdated": vi.is_outdated,
            "eol": vi.eol,
            "advisory_count": vi.advisory_count,
            "has_critical_advisories": vi.has_critical_advisories,
            "version_label": vi.version_label,
        }

        if vi.is_outdated:
            service.tags.append("outdated-version")
        if vi.eol:
            service.tags.append("end-of-life")
        if vi.has_critical_advisories:
            service.tags.append("critical-advisories")

        logger.info(
            f"Version intel for {platform} {detected_version}: "
            f"latest={latest_stable}, outdated={is_outdated}, "
            f"advisories={len(matched_advisories)}"
        )
        return vi

    def enrich_many(self, services: list[AIService]) -> list[VersionInfo]:
        """Enrich all services with version intelligence."""
        results = []
        for svc in services:
            vi = self.enrich(svc)
            if vi:
                results.append(vi)
        return results

    def _match_advisories(
        self,
        detected_version: str,
        advisories: list[SecurityAdvisory],
    ) -> list[SecurityAdvisory]:
        """Return advisories that apply to the detected version."""
        if detected_version in ("unknown", ""):
            return advisories

        matched = []
        for adv in advisories:
            for affected in adv.affected_versions:
                if self._version_matches_range(detected_version, affected):
                    matched.append(adv)
                    break
        return matched

    def _version_matches_range(self, version: str, range_spec: str) -> bool:
        """Check if a version matches a range specification like '<1.2.3'."""
        if range_spec.startswith("<"):
            boundary = range_spec[1:].strip()
            d = _parse_semver(version)
            b = _parse_semver(boundary)
            if d and b:
                return d < b
        elif range_spec.startswith("<="):
            boundary = range_spec[2:].strip()
            d = _parse_semver(version)
            b = _parse_semver(boundary)
            if d and b:
                return d <= b
        elif range_spec.startswith(">="):
            boundary = range_spec[2:].strip()
            d = _parse_semver(version)
            b = _parse_semver(boundary)
            if d and b:
                return d >= b
        elif range_spec == "*":
            return True
        else:
            return version == range_spec
        return False
