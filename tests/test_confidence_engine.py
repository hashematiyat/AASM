"""
Tests for Feature 7 — Confidence Engine
"""

from __future__ import annotations

import pytest

from aasm.modules.confidence.engine import (
    ConfidenceEngine,
    ConfidenceResult,
    ConfidenceLevel,
    SignalWeight,
    SIGNAL_DEFINITIONS,
)


class TestSignalWeight:
    def test_contribution_when_matched(self):
        sw = SignalWeight(name="test", description="test", weight=0.25, matched=True)
        assert sw.contribution == 0.25

    def test_contribution_when_not_matched(self):
        sw = SignalWeight(name="test", description="test", weight=0.25, matched=False)
        assert sw.contribution == 0.0


class TestSignalDefinitions:
    def test_all_signals_have_weight(self):
        for name, sig_def in SIGNAL_DEFINITIONS.items():
            assert "weight" in sig_def
            assert 0 < sig_def["weight"] <= 1.0

    def test_all_signals_have_description(self):
        for name, sig_def in SIGNAL_DEFINITIONS.items():
            assert "description" in sig_def and sig_def["description"]

    def test_at_least_10_signal_types_defined(self):
        assert len(SIGNAL_DEFINITIONS) >= 10


class TestConfidenceResult:
    def test_confidence_pct_formatting(self):
        r = ConfidenceResult(
            platform="Ollama",
            confidence=0.856,
            level=ConfidenceLevel.DEFINITIVE,
        )
        assert "86" in r.confidence_pct or "85" in r.confidence_pct

    def test_is_actionable_for_high(self):
        r = ConfidenceResult(
            platform="Ollama",
            confidence=0.75,
            level=ConfidenceLevel.HIGH,
        )
        assert r.is_actionable is True

    def test_not_actionable_for_insufficient(self):
        r = ConfidenceResult(
            platform="Ollama",
            confidence=0.05,
            level=ConfidenceLevel.INSUFFICIENT,
        )
        assert r.is_actionable is False

    def test_not_actionable_for_low(self):
        r = ConfidenceResult(
            platform="Ollama",
            confidence=0.20,
            level=ConfidenceLevel.LOW,
        )
        assert r.is_actionable is False

    def test_to_dict_structure(self):
        r = ConfidenceResult(
            platform="LiteLLM",
            confidence=0.80,
            level=ConfidenceLevel.DEFINITIVE,
        )
        d = r.to_dict()
        assert d["platform"] == "LiteLLM"
        assert d["confidence"] == 0.80
        assert "confidence_pct" in d
        assert "level" in d
        assert "is_actionable" in d
        assert "matched_signals" in d
        assert "contributing_engines" in d

    def test_to_dict_matched_signals_filtered(self):
        signals = [
            SignalWeight(name="s1", description="d1", weight=0.2, matched=True, value="v1"),
            SignalWeight(name="s2", description="d2", weight=0.1, matched=False, value=""),
        ]
        r = ConfidenceResult(
            platform="Test",
            confidence=0.5,
            level=ConfidenceLevel.MEDIUM,
            signals=signals,
        )
        d = r.to_dict()
        assert len(d["matched_signals"]) == 1
        assert d["matched_signals"][0]["name"] == "s1"


class TestConfidenceEngine:
    def test_definitive_confidence(self):
        engine = ConfidenceEngine()
        matched = {
            "explicit_version_header": "x-ollama-version: 0.3.14",
            "platform_json_key": "models",
            "html_exact_name": "Ollama",
            "server_header_match": "ollama",
            "specific_endpoint_responds": "/api/tags",
        }
        result = engine.score("Ollama", matched)
        assert result.confidence >= 0.80
        assert result.level == ConfidenceLevel.DEFINITIVE

    def test_insufficient_confidence_with_no_signals(self):
        engine = ConfidenceEngine()
        result = engine.score("Ollama", {})
        assert result.confidence == 0.0
        assert result.level == ConfidenceLevel.INSUFFICIENT

    def test_medium_confidence_partial_signals(self):
        engine = ConfidenceEngine()
        matched = {
            "specific_endpoint_responds": "/v1/models",
        }
        result = engine.score("OpenAI Compatible", matched)
        assert result.level in (ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)

    def test_score_returns_correct_platform(self):
        engine = ConfidenceEngine()
        result = engine.score("Flowise", {"platform_json_key": "chatflows"})
        assert result.platform == "Flowise"

    def test_corroboration_bonus_applied(self):
        engine = ConfidenceEngine()
        matched_single = {"specific_endpoint_responds": "/api/tags"}
        matched_multi = {
            "specific_endpoint_responds": "/api/tags",
            "platform_json_key": "models",
            "html_exact_name": "Ollama",
            "server_header_match": "ollama",
        }
        result_single = engine.score("Ollama", matched_single)
        result_multi = engine.score("Ollama", matched_multi)
        assert result_multi.confidence > result_single.confidence

    def test_contributing_engines_identified(self):
        engine = ConfidenceEngine()
        matched = {
            "explicit_version_header": "v0.3.14",
            "fingerprint_corroboration": "high",
            "endpoint_enumeration_corroboration": "3/5 endpoints",
            "version_intel_corroboration": "confirmed",
        }
        result = engine.score("Ollama", matched)
        assert "SmartDetectionEngine" in result.contributing_engines
        assert "DeepFingerprintEngine" in result.contributing_engines
        assert "EndpointEnumerationEngine" in result.contributing_engines
        assert "VersionIntelligenceEngine" in result.contributing_engines

    def test_combine_all_engines(self):
        engine = ConfidenceEngine()
        result = engine.combine(
            platform="LiteLLM",
            detector_confidence=0.85,
            fingerprint_confidence=0.75,
            enumeration_endpoint_ratio=0.60,
            version_confirmed=True,
        )
        assert result.platform == "LiteLLM"
        assert result.confidence > 0.5
        assert result.level in (ConfidenceLevel.HIGH, ConfidenceLevel.DEFINITIVE)

    def test_combine_detection_only(self):
        engine = ConfidenceEngine()
        result = engine.combine(
            platform="vLLM",
            detector_confidence=0.70,
        )
        assert result.platform == "vLLM"
        assert result.confidence > 0

    def test_combine_low_detection(self):
        engine = ConfidenceEngine()
        result = engine.combine(
            platform="UnknownPlatform",
            detector_confidence=0.20,
        )
        assert result.level in (ConfidenceLevel.INSUFFICIENT, ConfidenceLevel.LOW)

    def test_confidence_capped_at_1(self):
        engine = ConfidenceEngine()
        matched = {k: f"val-{k}" for k in SIGNAL_DEFINITIONS.keys()}
        result = engine.score("Ollama", matched)
        assert result.confidence <= 1.0

    def test_classify_level_boundaries(self):
        engine = ConfidenceEngine()
        assert engine._classify_level(0.80) == ConfidenceLevel.DEFINITIVE
        assert engine._classify_level(0.65) == ConfidenceLevel.HIGH
        assert engine._classify_level(0.40) == ConfidenceLevel.MEDIUM
        assert engine._classify_level(0.15) == ConfidenceLevel.LOW
        assert engine._classify_level(0.05) == ConfidenceLevel.INSUFFICIENT
