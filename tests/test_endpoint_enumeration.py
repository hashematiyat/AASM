"""
Tests for Feature 5 — Deep Endpoint Enumeration Engine
"""

from __future__ import annotations

import pytest
import httpx

from aasm.modules.enumeration.engine import (
    EndpointEnumerationEngine,
    EndpointResult,
    EndpointStatus,
    COMMON_AI_ENDPOINTS,
)


class TestEndpointResult:
    """Tests for EndpointResult dataclass."""

    def test_exists_true_for_unprotected(self):
        r = EndpointResult(
            path="/health",
            http_status=200,
            status=EndpointStatus.UNPROTECTED,
        )
        assert r.exists is True

    def test_exists_false_for_not_found(self):
        r = EndpointResult(
            path="/notexist",
            http_status=404,
            status=EndpointStatus.NOT_FOUND,
        )
        assert r.exists is False

    def test_publicly_accessible(self):
        r = EndpointResult(
            path="/health",
            http_status=200,
            status=EndpointStatus.UNPROTECTED,
            auth_required=False,
        )
        assert r.publicly_accessible is True

    def test_not_publicly_accessible_when_protected(self):
        r = EndpointResult(
            path="/api/admin",
            http_status=401,
            status=EndpointStatus.PROTECTED,
            auth_required=True,
        )
        assert r.publicly_accessible is False

    def test_not_publicly_accessible_when_sensitive_and_no_200(self):
        r = EndpointResult(
            path="/api/admin",
            http_status=403,
            status=EndpointStatus.PROTECTED,
            auth_required=True,
        )
        assert r.publicly_accessible is False


class TestCommonAIEndpoints:
    """Tests for the COMMON_AI_ENDPOINTS list."""

    def test_at_least_60_endpoints_defined(self):
        assert len(COMMON_AI_ENDPOINTS) >= 60

    def test_all_endpoints_have_path(self):
        for ep in COMMON_AI_ENDPOINTS:
            assert "path" in ep and ep["path"].startswith("/")

    def test_sensitive_endpoints_include_admin(self):
        admin_ep = next(
            (ep for ep in COMMON_AI_ENDPOINTS if ep["path"] == "/api/admin"),
            None,
        )
        assert admin_ep is not None
        assert admin_ep.get("sensitive") is True

    def test_health_endpoint_not_sensitive(self):
        health_ep = next(
            (ep for ep in COMMON_AI_ENDPOINTS if ep["path"] == "/health"),
            None,
        )
        assert health_ep is not None
        assert health_ep.get("sensitive") is False

    def test_key_generate_is_sensitive(self):
        ep = next(
            (ep for ep in COMMON_AI_ENDPOINTS if ep["path"] == "/v1/key/generate"),
            None,
        )
        assert ep is not None
        assert ep.get("sensitive") is True

    def test_metrics_is_sensitive(self):
        ep = next(
            (ep for ep in COMMON_AI_ENDPOINTS if ep["path"] == "/metrics"),
            None,
        )
        assert ep is not None
        assert ep.get("sensitive") is True

    def test_openapi_is_sensitive(self):
        ep = next(
            (ep for ep in COMMON_AI_ENDPOINTS if ep["path"] == "/openapi.json"),
            None,
        )
        assert ep is not None
        assert ep.get("sensitive") is True

    def test_mcp_sse_endpoint_present(self):
        paths = [ep["path"] for ep in COMMON_AI_ENDPOINTS]
        assert "/sse" in paths or "/mcp/sse" in paths

    def test_all_endpoints_have_notes(self):
        for ep in COMMON_AI_ENDPOINTS:
            assert "notes" in ep and len(ep["notes"]) > 0


class TestEndpointEnumerationEngine:
    """Tests for EndpointEnumerationEngine class."""

    def test_engine_instantiation_with_defaults(self):
        engine = EndpointEnumerationEngine()
        assert engine.timeout == 5.0
        assert engine.concurrency == 20
        assert engine.verify_ssl is False

    def test_engine_instantiation_with_custom_values(self):
        engine = EndpointEnumerationEngine(timeout=10.0, concurrency=10, verify_ssl=True)
        assert engine.timeout == 10.0
        assert engine.concurrency == 10
        assert engine.verify_ssl is True

    @pytest.mark.asyncio
    async def test_probe_endpoint_returns_not_found_on_failure(self):
        engine = EndpointEnumerationEngine(timeout=1.0)
        transport = httpx.MockTransport(
            lambda request: httpx.Response(404)
        )
        async with httpx.AsyncClient(transport=transport) as client:
            result = await engine._probe_endpoint(
                client,
                "http://fake-host:9999",
                {"path": "/health", "sensitive": False, "deprecated": False, "notes": ["test"]},
            )
        assert result.status == EndpointStatus.NOT_FOUND
        assert result.http_status == 404

    @pytest.mark.asyncio
    async def test_probe_endpoint_returns_unprotected_on_200(self):
        engine = EndpointEnumerationEngine()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await engine._probe_endpoint(
                client,
                "http://fake-host",
                {"path": "/health", "sensitive": False, "deprecated": False, "notes": []},
            )
        assert result.status == EndpointStatus.UNPROTECTED
        assert result.exists is True

    @pytest.mark.asyncio
    async def test_probe_endpoint_returns_sensitive_on_200_sensitive(self):
        engine = EndpointEnumerationEngine()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"data")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await engine._probe_endpoint(
                client,
                "http://fake-host",
                {"path": "/api/admin", "sensitive": True, "deprecated": False, "notes": ["admin"]},
            )
        assert result.status == EndpointStatus.SENSITIVE
        assert result.sensitive is True

    @pytest.mark.asyncio
    async def test_probe_endpoint_returns_protected_on_401(self):
        engine = EndpointEnumerationEngine()

        def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await engine._probe_endpoint(
                client,
                "http://fake-host",
                {"path": "/api/admin", "sensitive": True, "deprecated": False, "notes": []},
            )
        assert result.status == EndpointStatus.PROTECTED
        assert result.auth_required is True

    @pytest.mark.asyncio
    async def test_probe_endpoint_exception_returns_not_found(self):
        engine = EndpointEnumerationEngine(timeout=0.01)

        def mock_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            result = await engine._probe_endpoint(
                client,
                "http://fake-host",
                {"path": "/health", "sensitive": False, "deprecated": False, "notes": []},
            )
        assert result.status == EndpointStatus.NOT_FOUND
        assert result.http_status is None
