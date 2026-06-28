"""
Feature 7 — Confidence Engine
Aggregates evidence from all detection, fingerprinting, and enumeration engines
into a single, calibrated confidence score for platform identification.

Confidence calculation model:
  - Primary identification (platform + explicit header/JSON): 0.85–1.0
  - Multi-signal corroboration (3+ signal types match): 0.65–0.84
  - Partial evidence (1–2 signal types, no definitive marker): 0.35–0.64
  - Weak signal (single soft match): 0.10–0.34
  - Below threshold: 0.00–0.09 (not reported)

Signals are weighted by specificity:
  - Explicit version header: very high
  - Platform-specific JSON key: high
  - HTML/title contains exact platform name: high
  - Specific API endpoint responding: medium
  - Generic response structure: low
  - Single cookie name: low
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConfidenceLevel(str, Enum):
    DEFINITIVE = "DEFINITIVE"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass
class SignalWeight:
    """A weighted evidence signal used in confidence calculation."""
    name: str
    description: str
    weight: float
    matched: bool = False
    value: str = ""

    @property
    def contribution(self) -> float:
        return self.weight if self.matched else 0.0


@dataclass
class ConfidenceResult:
    """
    Aggregated confidence result for a platform identification decision.
    Combines evidence from detection engine, fingerprinter, and enumeration.
    """
    platform: str
    confidence: float
    level: ConfidenceLevel
    signals: list[SignalWeight] = field(default_factory=list)
    contributing_engines: list[str] = field(default_factory=list)
    raw_scores: dict[str, float] = field(default_factory=dict)

    @property
    def confidence_pct(self) -> str:
        return f"{self.confidence * 100:.0f}%"

    @property
    def is_actionable(self) -> bool:
        return self.level not in (ConfidenceLevel.INSUFFICIENT, ConfidenceLevel.LOW)

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "confidence": self.confidence,
            "confidence_pct": self.confidence_pct,
            "level": self.level.value,
            "is_actionable": self.is_actionable,
            "matched_signals": [
                {"name": s.name, "value": s.value, "weight": s.weight}
                for s in self.signals if s.matched
            ],
            "contributing_engines": self.contributing_engines,
            "raw_scores": self.raw_scores,
        }


SIGNAL_DEFINITIONS: dict[str, dict[str, Any]] = {
    "explicit_version_header": {
        "description": "Explicit version header (e.g., X-LiteLLM-Version: 1.0)",
        "weight": 0.30,
    },
    "platform_json_key": {
        "description": "Platform-specific key found in JSON response body",
        "weight": 0.25,
    },
    "html_exact_name": {
        "description": "Exact platform name in HTML title or body",
        "weight": 0.20,
    },
    "server_header_match": {
        "description": "Server: header matches platform name",
        "weight": 0.25,
    },
    "specific_endpoint_responds": {
        "description": "Platform-unique API endpoint returns 2xx",
        "weight": 0.15,
    },
    "openapi_title_match": {
        "description": "OpenAPI spec title identifies platform",
        "weight": 0.15,
    },
    "cookie_match": {
        "description": "Session cookie name matches platform pattern",
        "weight": 0.10,
    },
    "error_signature_match": {
        "description": "Error page contains platform-specific text",
        "weight": 0.10,
    },
    "favicon_hash_match": {
        "description": "Favicon MD5 hash matches known platform",
        "weight": 0.20,
    },
    "js_bundle_signature": {
        "description": "JavaScript bundle contains platform-specific identifiers",
        "weight": 0.10,
    },
    "generic_openai_compat": {
        "description": "OpenAI-compatible response structure detected",
        "weight": 0.05,
    },
    "version_intel_corroboration": {
        "description": "Version intelligence DB confirms platform version exists",
        "weight": 0.10,
    },
    "endpoint_enumeration_corroboration": {
        "description": "Multiple platform-specific endpoints found active",
        "weight": 0.15,
    },
    "fingerprint_corroboration": {
        "description": "Deep fingerprint analysis matches platform profile",
        "weight": 0.15,
    },
}


class ConfidenceEngine:
    """
    Aggregates confidence signals from all detection engines.
    Produces a calibrated ConfidenceResult for a given platform candidate.
    """

    LEVEL_THRESHOLDS = [
        (0.80, ConfidenceLevel.DEFINITIVE),
        (0.60, ConfidenceLevel.HIGH),
        (0.35, ConfidenceLevel.MEDIUM),
        (0.10, ConfidenceLevel.LOW),
        (0.00, ConfidenceLevel.INSUFFICIENT),
    ]

    def score(
        self,
        platform: str,
        matched_signals: dict[str, str],
        raw_scores: dict[str, float] | None = None,
    ) -> ConfidenceResult:
        """
        Produce a ConfidenceResult given a set of matched signals.

        Args:
            platform: Platform name.
            matched_signals: Dict mapping signal_name → matched_value.
                             Keys must be from SIGNAL_DEFINITIONS.
            raw_scores: Optional per-engine raw scores for transparency.

        Returns:
            A calibrated ConfidenceResult.
        """
        signals: list[SignalWeight] = []
        total = 0.0

        for sig_name, sig_def in SIGNAL_DEFINITIONS.items():
            matched = sig_name in matched_signals
            signals.append(SignalWeight(
                name=sig_name,
                description=sig_def["description"],
                weight=sig_def["weight"],
                matched=matched,
                value=matched_signals.get(sig_name, ""),
            ))
            if matched:
                total += sig_def["weight"]

        total = self._apply_corroboration_bonus(total, signals)
        confidence = min(total, 1.0)
        level = self._classify_level(confidence)

        contributing = self._identify_engines(matched_signals)

        return ConfidenceResult(
            platform=platform,
            confidence=confidence,
            level=level,
            signals=signals,
            contributing_engines=contributing,
            raw_scores=raw_scores or {},
        )

    def combine(
        self,
        platform: str,
        detector_confidence: float,
        fingerprint_confidence: float | None = None,
        enumeration_endpoint_ratio: float | None = None,
        version_confirmed: bool = False,
    ) -> ConfidenceResult:
        """
        Combine per-engine confidence scores from different engines using
        weighted averaging with corroboration bonuses.

        Args:
            platform: Platform name.
            detector_confidence: Confidence from SmartDetectionEngine (0–1).
            fingerprint_confidence: Confidence from DeepFingerprintEngine (0–1).
            enumeration_endpoint_ratio: Ratio of expected endpoints found (0–1).
            version_confirmed: Whether VersionIntelligenceEngine confirmed the version.

        Returns:
            A combined ConfidenceResult.
        """
        matched: dict[str, str] = {}
        raw: dict[str, float] = {"detection": detector_confidence}

        if detector_confidence >= 0.30:
            matched["specific_endpoint_responds"] = f"detection={detector_confidence:.2f}"

        if detector_confidence >= 0.60:
            matched["platform_json_key"] = f"detection={detector_confidence:.2f}"

        if detector_confidence >= 0.80:
            matched["explicit_version_header"] = f"detection={detector_confidence:.2f}"

        if fingerprint_confidence is not None:
            raw["fingerprint"] = fingerprint_confidence
            if fingerprint_confidence >= 0.40:
                matched["fingerprint_corroboration"] = f"fp={fingerprint_confidence:.2f}"
            if fingerprint_confidence >= 0.70:
                matched["html_exact_name"] = f"fp={fingerprint_confidence:.2f}"

        if enumeration_endpoint_ratio is not None:
            raw["enumeration"] = enumeration_endpoint_ratio
            if enumeration_endpoint_ratio >= 0.30:
                matched["endpoint_enumeration_corroboration"] = f"enum={enumeration_endpoint_ratio:.2f}"

        if version_confirmed:
            matched["version_intel_corroboration"] = "confirmed"

        return self.score(platform, matched, raw)

    def _apply_corroboration_bonus(
        self, base_score: float, signals: list[SignalWeight]
    ) -> float:
        """Apply a small bonus when multiple independent signal types match."""
        matched_count = sum(1 for s in signals if s.matched)
        if matched_count >= 4:
            bonus = 0.10
        elif matched_count == 3:
            bonus = 0.05
        elif matched_count == 2:
            bonus = 0.02
        else:
            bonus = 0.0
        return base_score + bonus

    def _classify_level(self, confidence: float) -> ConfidenceLevel:
        for threshold, level in self.LEVEL_THRESHOLDS:
            if confidence >= threshold:
                return level
        return ConfidenceLevel.INSUFFICIENT

    def _identify_engines(self, matched_signals: dict[str, str]) -> list[str]:
        engines = []
        engine_signal_map = {
            "SmartDetectionEngine": {
                "explicit_version_header", "server_header_match",
                "platform_json_key", "html_exact_name",
                "specific_endpoint_responds", "openapi_title_match",
                "cookie_match", "error_signature_match",
            },
            "DeepFingerprintEngine": {
                "fingerprint_corroboration", "favicon_hash_match",
                "js_bundle_signature",
            },
            "EndpointEnumerationEngine": {
                "endpoint_enumeration_corroboration",
            },
            "VersionIntelligenceEngine": {
                "version_intel_corroboration",
            },
        }
        for engine, signals in engine_signal_map.items():
            if any(s in matched_signals for s in signals):
                engines.append(engine)
        return engines
