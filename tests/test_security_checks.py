"""
Tests for Feature 4 — AI Security Assessment Checks
"""

from __future__ import annotations

import pytest
import httpx

from aasm.modules.assessment.checks.auth import AuthenticationChecks
from aasm.modules.assessment.checks.authorization import AuthorizationChecks
from aasm.modules.assessment.checks.ai_security import AISecurityChecks
from aasm.modules.assessment.checks.infrastructure import InfrastructureChecks
from aasm.modules.assessment.checks.secrets import SecretsChecks
from aasm.core.models import AIService, AIServiceType, AuthType, SecurityFinding, Severity


def make_service(
    auth_required: bool = False,
    platform: str = "Ollama",
    endpoints: list[str] | None = None,
) -> AIService:
    svc = AIService(
        host="127.0.0.1",
        port=11434,
        url="http://127.0.0.1:11434",
        service_type=AIServiceType.LOCAL_LLM,
        platform=platform,
        version="0.3.14",
        auth_required=auth_required,
        auth_type=AuthType.NONE if not auth_required else AuthType.BEARER_TOKEN,
    )
    svc.endpoints = endpoints or []
    svc.tls = False
    return svc


def make_http_mock(responses: dict[str, tuple[int, str]]):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path in responses:
            status, body = responses[path]
            return httpx.Response(status, text=body)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


class TestAuthenticationChecks:
    @pytest.mark.asyncio
    async def test_no_auth_finding_raised(self):
        svc = make_service(auth_required=False)
        checks = AuthenticationChecks()
        transport = make_http_mock({
            "/api/v1/chatflows": (404, ""),
            "/api/v1/credentials": (404, ""),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_no_auth(client, svc)
        assert len(findings) == 1
        assert findings[0].category == "Authentication"
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_no_auth_finding_not_raised_when_auth_required(self):
        svc = make_service(auth_required=True)
        checks = AuthenticationChecks()
        transport = make_http_mock({})
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_no_auth(client, svc)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_anonymous_access_finding_raised(self):
        svc = make_service()
        checks = AuthenticationChecks()
        transport = make_http_mock({
            "/api/v1/chatflows": (200, '{"chatflows": []}'),
            "/v1/key/generate": (200, '{"key": "abc"}'),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_anonymous_access(client, svc)
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_api_key_exposure_finding(self):
        svc = make_service()
        checks = AuthenticationChecks()
        transport = make_http_mock({
            "/api/v1/apikey": (200, '[{"apiKey": "sk-test-123", "id": 1}]'),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_api_key_exposure(client, svc)
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL


class TestAuthorizationChecks:
    @pytest.mark.asyncio
    async def test_broken_access_control_finding(self):
        svc = make_service()
        checks = AuthorizationChecks()
        transport = make_http_mock({
            "/api/admin": (200, "admin panel"),
            "/api/admin/config": (200, "config data"),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_broken_access_control(client, svc)
        assert len(findings) > 0
        assert findings[0].category == "Authorization"
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_no_broken_access_when_all_protected(self):
        svc = make_service()
        checks = AuthorizationChecks()
        transport = make_http_mock({path: (401, "") for path in ["/api/admin", "/api/admin/config"]})
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_broken_access_control(client, svc)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_missing_authorization_finding(self):
        svc = make_service()
        checks = AuthorizationChecks()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text='{"data": []}')

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_missing_authorization(client, svc)
        assert len(findings) > 0
        assert findings[0].title == "Authorization Not Enforced — Invalid Token Accepted"


class TestInfrastructureChecks:
    @pytest.mark.asyncio
    async def test_metrics_finding_on_prometheus_response(self):
        svc = make_service()
        checks = InfrastructureChecks()
        prometheus_body = "# HELP request_total Total requests\n# TYPE request_total counter\nrequest_total 42\n"
        transport = make_http_mock({
            "/metrics": (200, prometheus_body),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_metrics_exposure(client, svc)
        assert len(findings) > 0
        assert "Prometheus" in findings[0].title

    @pytest.mark.asyncio
    async def test_no_metrics_finding_when_protected(self):
        svc = make_service()
        checks = InfrastructureChecks()
        transport = make_http_mock({"/metrics": (401, "")})
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_metrics_exposure(client, svc)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_swagger_exposure_finding(self):
        svc = make_service()
        checks = InfrastructureChecks()
        transport = make_http_mock({
            "/docs": (200, "<html><body>swagger ui openapi</body></html>"),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_swagger_exposure(client, svc)
        assert len(findings) > 0
        assert "Swagger" in findings[0].title

    @pytest.mark.asyncio
    async def test_admin_panel_finding(self):
        svc = make_service()
        checks = InfrastructureChecks()
        transport = make_http_mock({
            "/admin": (200, "welcome to admin"),
        })
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_admin_panels(client, svc)
        assert len(findings) > 0
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_openapi_spec_finding(self):
        svc = make_service()
        checks = InfrastructureChecks()
        spec = '{"info": {"title": "My AI API", "version": "1.0"}, "paths": {"/v1/models": {}}}'
        transport = make_http_mock({"/openapi.json": (200, spec)})
        async with httpx.AsyncClient(transport=transport) as client:
            findings = await checks._check_openapi_exposure(client, svc)
        assert len(findings) > 0
        assert "OpenAPI" in findings[0].title


class TestSecretsChecks:
    def test_openai_key_detected(self):
        checks = SecretsChecks()
        body = 'some config: OPENAI_API_KEY="sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"'
        svc = make_service()
        findings = checks._scan_body(body, svc, "/api/config")
        assert len(findings) > 0
        assert any("OpenAI" in f.title for f in findings)

    def test_aws_access_key_detected(self):
        checks = SecretsChecks()
        body = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        svc = make_service()
        findings = checks._scan_body(body, svc, "/config")
        assert len(findings) > 0
        assert any("AWS" in f.title for f in findings)

    def test_private_key_detected(self):
        checks = SecretsChecks()
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        svc = make_service()
        findings = checks._scan_body(body, svc, "/certs")
        assert len(findings) > 0
        assert any("Private Key" in f.title for f in findings)

    def test_database_url_detected(self):
        checks = SecretsChecks()
        body = "DATABASE_URL=postgresql://admin:supersecret@db.example.com/mydb"
        svc = make_service()
        findings = checks._scan_body(body, svc, "/config")
        assert len(findings) > 0
        assert any("Database" in f.title for f in findings)

    def test_github_token_detected(self):
        checks = SecretsChecks()
        body = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        svc = make_service()
        findings = checks._scan_body(body, svc, "/env")
        assert len(findings) > 0

    def test_no_false_positive_on_clean_body(self):
        checks = SecretsChecks()
        body = '{"health": "ok", "version": "1.0.0", "status": "running"}'
        svc = make_service()
        findings = checks._scan_body(body, svc, "/health")
        assert len(findings) == 0

    def test_deduplication_prevents_multiple_findings_for_same_type(self):
        checks = SecretsChecks()
        body = (
            'key1="sk-abcdefghijklmnopqrstuvwxyz1234567890AB" '
            'key2="sk-abcdefghijklmnopqrstuvwxyz1234567890CD"'
        )
        svc = make_service()
        findings = checks._scan_body(body, svc, "/config")
        openai_findings = [f for f in findings if "OpenAI" in f.title]
        assert len(openai_findings) == 1

    def test_critical_severity_for_openai_key(self):
        checks = SecretsChecks()
        body = 'token = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"'
        svc = make_service()
        findings = checks._scan_body(body, svc, "/config")
        openai = next((f for f in findings if "OpenAI" in f.title), None)
        if openai:
            assert openai.severity == Severity.CRITICAL

    def test_evidence_contains_redacted_sample(self):
        checks = SecretsChecks()
        body = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz1234567890ABCD"'
        svc = make_service()
        findings = checks._scan_body(body, svc, "/config")
        for f in findings:
            if f.evidence:
                sample = f.evidence.get("sample", "")
                assert "REDACTED" in sample


class TestAISecurityChecks:
    def test_chat_url_ollama(self):
        svc = make_service(platform="Ollama")
        checks = AISecurityChecks()
        url = checks._chat_url(svc)
        assert url == "http://127.0.0.1:11434/api/chat"

    def test_chat_url_openai_compat(self):
        svc = make_service(platform="vLLM", endpoints=["/v1/chat/completions"])
        checks = AISecurityChecks()
        url = checks._chat_url(svc)
        assert "chat/completions" in url

    def test_chat_url_none_when_no_endpoint(self):
        svc = make_service(platform="UnknownPlatform", endpoints=["/health"])
        checks = AISecurityChecks()
        url = checks._chat_url(svc)
        assert url is None
