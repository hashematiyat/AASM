"""
Tests for Feature 1 — Deep Fingerprinting Engine
"""

from __future__ import annotations

import pytest
import httpx

from aasm.modules.fingerprint.deep import (
    DeepFingerprintEngine,
    DeepFingerprint,
    NetworkFingerprint,
    ServiceFingerprint,
    SecurityFingerprint,
    AICapabilityFingerprint,
    PerformanceFingerprint,
)
from aasm.core.models import AIService, AIServiceType, AuthType, AIModel


def make_service(
    platform: str = "Ollama",
    version: str = "0.3.14",
    url: str = "http://127.0.0.1:11434",
    auth_required: bool = False,
    models: list[AIModel] | None = None,
    endpoints: list[str] | None = None,
    tls: bool = False,
) -> AIService:
    svc = AIService(
        host="127.0.0.1",
        port=11434,
        url=url,
        service_type=AIServiceType.LOCAL_LLM,
        platform=platform,
        version=version,
        auth_required=auth_required,
        auth_type=AuthType.NONE,
    )
    svc.models = models or []
    svc.endpoints = endpoints or []
    svc.tls = tls
    return svc


class TestNetworkFingerprint:
    def test_defaults(self):
        nf = NetworkFingerprint()
        assert nf.protocol == "http"
        assert nf.http2_supported is False
        assert nf.websocket_supported is False
        assert nf.grpc_detected is False


class TestServiceFingerprint:
    def test_defaults(self):
        sf = ServiceFingerprint()
        assert sf.product_name == ""
        assert sf.vendor == ""


class TestSecurityFingerprint:
    def test_defaults(self):
        sec = SecurityFingerprint()
        assert sec.cors_wildcard is False
        assert sec.rate_limiting is False
        assert sec.security_headers == {}


class TestAICapabilityFingerprint:
    def test_defaults(self):
        aif = AICapabilityFingerprint()
        assert aif.models == []
        assert aif.streaming_supported is False
        assert aif.mcp_supported is False


class TestPerformanceFingerprint:
    def test_defaults(self):
        pf = PerformanceFingerprint()
        assert pf.gpu_enabled is False
        assert pf.response_time_ms is None


class TestDeepFingerprint:
    def test_to_dict_structure(self):
        fp = DeepFingerprint(service_url="http://localhost:11434", confidence=0.85)
        d = fp.to_dict()
        assert "service_url" in d
        assert "network" in d
        assert "service" in d
        assert "security" in d
        assert "ai_capabilities" in d
        assert "performance" in d
        assert "confidence" in d
        assert d["service_url"] == "http://localhost:11434"
        assert d["confidence"] == 0.85

    def test_to_dict_nested_network(self):
        fp = DeepFingerprint()
        fp.network.server_banner = "nginx/1.24"
        d = fp.to_dict()
        assert d["network"]["server_banner"] == "nginx/1.24"

    def test_to_dict_security_headers(self):
        fp = DeepFingerprint()
        fp.security.cors_wildcard = True
        fp.security.missing_headers = ["x-frame-options", "content-security-policy"]
        d = fp.to_dict()
        assert d["security"]["cors_wildcard"] is True
        assert len(d["security"]["missing_headers"]) == 2


class TestDeepFingerprintEngine:
    def test_instantiation_defaults(self):
        engine = DeepFingerprintEngine()
        assert engine.timeout == 10.0
        assert engine.verify_ssl is False

    def test_instantiation_custom(self):
        engine = DeepFingerprintEngine(timeout=5.0, verify_ssl=True)
        assert engine.timeout == 5.0
        assert engine.verify_ssl is True

    def test_detect_framework_fastapi(self):
        engine = DeepFingerprintEngine()
        assert "FastAPI" in engine._detect_framework_from_server("uvicorn")

    def test_detect_framework_flask(self):
        engine = DeepFingerprintEngine()
        assert "Flask" in engine._detect_framework_from_server("werkzeug/3.0")

    def test_detect_framework_gradio(self):
        engine = DeepFingerprintEngine()
        assert engine._detect_framework_from_server("gradio") == "Gradio"

    def test_detect_framework_unknown(self):
        engine = DeepFingerprintEngine()
        assert engine._detect_framework_from_server("unknown-server") == ""

    def test_compute_confidence_full(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint()
        fp.service.product_name = "Ollama"
        fp.network.server_banner = "ollama/0.3.14"
        fp.service.version = "0.3.14"
        fp.ai_capabilities.models = ["llama3.2"]
        fp.security.security_headers = {"x-frame-options": "SAMEORIGIN"}
        fp.network.tls_version = "TLSv1.3"
        svc = make_service()
        engine._compute_confidence(fp, svc)
        assert fp.confidence > 0.5

    def test_compute_confidence_empty(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint()
        svc = make_service(platform="")
        engine._compute_confidence(fp, svc)
        assert fp.confidence < 0.5

    def test_store_in_metadata_sets_deep_fingerprint(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint(confidence=0.9)
        svc = make_service()
        engine._store_in_metadata(svc, fp)
        assert "deep_fingerprint" in svc.metadata

    def test_store_in_metadata_cors_wildcard_adds_tag(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint()
        fp.security.cors_wildcard = True
        svc = make_service()
        engine._store_in_metadata(svc, fp)
        assert "cors-wildcard" in svc.tags

    def test_store_in_metadata_mcp_adds_tag(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint()
        fp.ai_capabilities.mcp_supported = True
        svc = make_service()
        engine._store_in_metadata(svc, fp)
        assert "mcp-enabled" in svc.tags

    def test_fingerprint_ai_capabilities_streaming(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint()
        svc = make_service(endpoints=["/api/generate", "/v1/models"])

        import asyncio

        async def run():
            transport = httpx.MockTransport(
                lambda r: httpx.Response(404)
            )
            async with httpx.AsyncClient(transport=transport) as client:
                await engine._fingerprint_ai(client, svc, fp)

        asyncio.run(run())
        assert fp.ai_capabilities.streaming_supported is True

    def test_fingerprint_ai_capabilities_agent_for_crewai(self):
        engine = DeepFingerprintEngine()
        fp = DeepFingerprint()
        svc = make_service(platform="CrewAI")

        import asyncio

        async def run():
            transport = httpx.MockTransport(lambda r: httpx.Response(404))
            async with httpx.AsyncClient(transport=transport) as client:
                await engine._fingerprint_ai(client, svc, fp)

        asyncio.run(run())
        assert fp.ai_capabilities.agent_supported is True

    def test_detect_reverse_proxy_from_server_banner(self):
        engine = DeepFingerprintEngine()
        headers = httpx.Headers({"server": "nginx/1.24.0"})
        assert engine._detect_reverse_proxy(headers) == "nginx"

    def test_detect_deployment_cloudflare(self):
        engine = DeepFingerprintEngine()
        headers = httpx.Headers({"cf-ray": "abc123", "server": "cloudflare"})
        deployment = engine._detect_deployment_type(headers, "cloudflare")
        assert "Cloudflare" in deployment

    def test_detect_deployment_self_hosted(self):
        engine = DeepFingerprintEngine()
        headers = httpx.Headers({"server": "uvicorn"})
        deployment = engine._detect_deployment_type(headers, "uvicorn")
        assert deployment == "Self-hosted"
