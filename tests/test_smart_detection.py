"""
Tests for Feature 2 — Smart Detection Engine
"""

from __future__ import annotations

import pytest
import httpx

from aasm.modules.detection.engine import SmartDetectionEngine, PlatformDetectionResult, DetectionSignal
from aasm.modules.detection.signatures import PLATFORM_SIGNATURES, PlatformSignature


class TestPlatformSignatures:
    """Tests for platform signature definitions."""

    def test_all_platforms_have_platform_name(self):
        for name, sig in PLATFORM_SIGNATURES.items():
            assert sig.platform, f"{name} is missing platform name"

    def test_all_platforms_have_probe_paths(self):
        for name, sig in PLATFORM_SIGNATURES.items():
            assert sig.probe_paths, f"{name} has no probe paths"

    def test_all_platforms_have_at_least_one_signal_type(self):
        for name, sig in PLATFORM_SIGNATURES.items():
            has_signals = any([
                sig.header_signals,
                sig.json_signals,
                sig.html_signals,
                sig.path_signals,
            ])
            assert has_signals, f"{name} has no detection signals"

    def test_ollama_has_correct_signals(self):
        sig = PLATFORM_SIGNATURES["Ollama"]
        assert "/api/tags" in sig.probe_paths
        assert "/api/generate" in sig.path_signals
        assert "models" in sig.json_signals

    def test_litellm_has_correct_signals(self):
        sig = PLATFORM_SIGNATURES["LiteLLM"]
        assert "litellm_version" in sig.json_signals

    def test_flowise_has_correct_signals(self):
        sig = PLATFORM_SIGNATURES["Flowise"]
        assert "/api/v1/chatflows" in sig.path_signals

    def test_dify_has_correct_signals(self):
        sig = PLATFORM_SIGNATURES["Dify"]
        assert "Dify" in sig.html_signals

    def test_langgraph_has_ok_path(self):
        sig = PLATFORM_SIGNATURES["LangGraph"]
        assert "/ok" in sig.probe_paths

    def test_all_19_platforms_defined(self):
        expected = {
            "Ollama", "Open WebUI", "LiteLLM", "vLLM", "LM Studio",
            "Flowise", "Dify", "Langflow", "AnythingLLM", "LocalAI",
            "HuggingFace TGI", "OpenRouter", "CrewAI", "AutoGen",
            "LangGraph", "OpenHands", "FastChat", "Text Generation WebUI",
            "OpenAI Compatible",
        }
        assert expected.issubset(set(PLATFORM_SIGNATURES.keys()))


class TestPlatformDetectionResult:
    """Tests for PlatformDetectionResult dataclass."""

    def test_confidence_pct_formatting(self):
        result = PlatformDetectionResult(platform="Ollama", confidence=0.85)
        assert result.confidence_pct == "85%"

    def test_confidence_pct_zero(self):
        result = PlatformDetectionResult(platform="Ollama", confidence=0.0)
        assert result.confidence_pct == "0%"

    def test_matched_by_from_signals(self):
        result = PlatformDetectionResult(
            platform="Ollama",
            confidence=0.8,
            signals=[
                DetectionSignal(
                    signal_type="HTTP Header",
                    signal_value="ollama",
                    matched_pattern="server: ollama",
                    confidence_contribution=0.4,
                )
            ],
        )
        assert "HTTP Header: server: ollama" in result.matched_by

    def test_empty_signals(self):
        result = PlatformDetectionResult(platform="Ollama", confidence=0.5)
        assert result.matched_by == []


class TestSmartDetectionEngineScoringLogic:
    """Unit tests for internal scoring methods (no HTTP needed)."""

    def _make_engine(self) -> SmartDetectionEngine:
        client = httpx.AsyncClient()
        return SmartDetectionEngine(client=client)

    def test_match_headers_exact(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        matched = engine._match_headers(sig, {"server": "ollama"})
        assert len(matched) > 0

    def test_match_headers_no_match(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        matched = engine._match_headers(sig, {"server": "nginx"})
        assert len(matched) == 0

    def test_match_json_by_key(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        evidence = {"json_keys": ["models", "version"], "json_values": []}
        matched = engine._match_json(sig, evidence)
        assert "models" in matched

    def test_match_json_no_match(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        evidence = {"json_keys": ["users", "teams"], "json_values": []}
        matched = engine._match_json(sig, evidence)
        assert len(matched) == 0

    def test_match_html_by_name(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Dify"]
        # _probe_root stores html_content already lowercased, replicate that here
        evidence = {
            "html_content": "<html>welcome to dify dashboard</html>",
            "html_title": "dify",
        }
        matched = engine._match_html(sig, evidence)
        assert len(matched) > 0

    def test_match_paths_subset(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        responsive = ["/api/version", "/api/tags", "/api/generate"]
        matched = engine._match_paths(sig, responsive)
        assert len(matched) > 0

    def test_score_platform_no_evidence(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        evidence = {
            "headers": {},
            "json_keys": [],
            "json_values": [],
            "html_content": "",
            "html_title": "",
            "paths_responsive": [],
            "cookie_names": [],
            "error_content": "",
            "openapi_title": "",
            "openapi_paths": [],
        }
        result = engine._score_platform(sig, evidence)
        assert result.confidence < SmartDetectionEngine.CONFIDENCE_THRESHOLD

    def test_score_platform_with_strong_evidence(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        evidence = {
            "headers": {"server": "ollama"},
            "json_keys": ["models", "version", "model_info"],
            "json_values": ["ollama", "v0.1.34"],
            "html_content": "ollama",
            "html_title": "ollama",
            "paths_responsive": ["/api/tags", "/api/version", "/api/generate"],
            "cookie_names": [],
            "error_content": "",
            "openapi_title": "",
            "openapi_paths": [],
        }
        result = engine._score_platform(sig, evidence)
        assert result.confidence >= SmartDetectionEngine.CONFIDENCE_THRESHOLD

    def test_score_platform_returns_correct_platform_name(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Flowise"]
        evidence = {
            "headers": {},
            "json_keys": ["chatflows", "chatflowId"],
            "json_values": [],
            "html_content": "flowise",
            "html_title": "flowise",
            "paths_responsive": ["/api/v1/chatflows", "/api/v1/tools"],
            "cookie_names": [],
            "error_content": "",
            "openapi_title": "",
            "openapi_paths": [],
        }
        result = engine._score_platform(sig, evidence)
        assert result.platform == "Flowise"

    def test_match_cookies(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Open WebUI"]
        matched = engine._match_cookies(sig, ["openwebui-session", "other-cookie"])
        assert "openwebui-session" in matched

    def test_match_errors(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["Ollama"]
        matched = engine._match_errors(sig, "Error: model not found in ollama registry")
        assert len(matched) > 0

    def test_match_openapi(self):
        engine = self._make_engine()
        sig = PLATFORM_SIGNATURES["LiteLLM"]
        evidence = {
            "openapi_title": "litellm proxy server",
            "openapi_paths": ["/health", "/v1/models"],
        }
        matched = engine._match_openapi(sig, evidence)
        assert len(matched) > 0
