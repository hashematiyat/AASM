"""
Feature 5 — Deep Endpoint Enumeration Engine
Systematically enumerates common AI platform endpoints and characterises each
one: exists / protected / unprotected / sensitive / deprecated.
Discovered endpoints are integrated back into the AIService and enrich the
fingerprinting and security check pipelines.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from aasm.core.logger import get_logger
from aasm.core.models import AIService

logger = get_logger("enumeration")


class EndpointStatus(str, Enum):
    EXISTS = "exists"
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    SENSITIVE = "sensitive"
    DEPRECATED = "deprecated"
    NOT_FOUND = "not_found"


@dataclass
class EndpointResult:
    """Result for a single enumerated endpoint."""
    path: str
    http_status: int | None
    status: EndpointStatus
    content_type: str = ""
    response_size: int = 0
    sensitive: bool = False
    deprecated: bool = False
    auth_required: bool = False
    notes: list[str] = field(default_factory=list)
    confidence: float = 1.0

    @property
    def exists(self) -> bool:
        return self.status != EndpointStatus.NOT_FOUND

    @property
    def publicly_accessible(self) -> bool:
        return self.http_status == 200 and not self.auth_required


COMMON_AI_ENDPOINTS: list[dict[str, Any]] = [
    # ── Health / Status ────────────────────────────────────────────────────────
    {"path": "/health",            "sensitive": False, "deprecated": False, "notes": ["Health check endpoint"]},
    {"path": "/healthz",           "sensitive": False, "deprecated": False, "notes": ["Kubernetes health probe"]},
    {"path": "/readyz",            "sensitive": False, "deprecated": False, "notes": ["Kubernetes readiness probe"]},
    {"path": "/livez",             "sensitive": False, "deprecated": False, "notes": ["Kubernetes liveness probe"]},
    {"path": "/status",            "sensitive": False, "deprecated": False, "notes": ["Service status endpoint"]},
    {"path": "/ping",              "sensitive": False, "deprecated": False, "notes": ["Ping / heartbeat endpoint"]},
    {"path": "/ok",                "sensitive": False, "deprecated": False, "notes": ["Simple availability check"]},
    # ── Version / Info ─────────────────────────────────────────────────────────
    {"path": "/version",           "sensitive": False, "deprecated": False, "notes": ["Version information"]},
    {"path": "/api/version",       "sensitive": False, "deprecated": False, "notes": ["API version"]},
    {"path": "/api/v1/version",    "sensitive": False, "deprecated": False, "notes": ["Versioned API version endpoint"]},
    {"path": "/info",              "sensitive": False, "deprecated": False, "notes": ["Service information"]},
    {"path": "/api/info",          "sensitive": False, "deprecated": False, "notes": ["API information"]},
    {"path": "/build",             "sensitive": False, "deprecated": False, "notes": ["Build metadata"]},
    # ── Model Endpoints ────────────────────────────────────────────────────────
    {"path": "/api/models",        "sensitive": False, "deprecated": False, "notes": ["Model listing"]},
    {"path": "/api/tags",          "sensitive": False, "deprecated": False, "notes": ["Ollama model tags"]},
    {"path": "/v1/models",         "sensitive": False, "deprecated": False, "notes": ["OpenAI-compatible model list"]},
    {"path": "/models",            "sensitive": False, "deprecated": False, "notes": ["Model list"]},
    {"path": "/api/ps",            "sensitive": True,  "deprecated": False, "notes": ["Running model processes (Ollama)"]},
    {"path": "/api/v1/models",     "sensitive": False, "deprecated": False, "notes": ["Versioned model API"]},
    # ── Documentation ─────────────────────────────────────────────────────────
    {"path": "/docs",              "sensitive": True,  "deprecated": False, "notes": ["API documentation (may expose API surface)"]},
    {"path": "/redoc",             "sensitive": True,  "deprecated": False, "notes": ["ReDoc API documentation"]},
    {"path": "/swagger",           "sensitive": True,  "deprecated": False, "notes": ["Swagger UI"]},
    {"path": "/swagger-ui",        "sensitive": True,  "deprecated": False, "notes": ["Swagger UI"]},
    {"path": "/swagger.json",      "sensitive": True,  "deprecated": False, "notes": ["Swagger spec"]},
    {"path": "/openapi.json",      "sensitive": True,  "deprecated": False, "notes": ["OpenAPI spec — exposes full API"]},
    {"path": "/openapi.yaml",      "sensitive": True,  "deprecated": False, "notes": ["OpenAPI YAML spec"]},
    {"path": "/api/schema",        "sensitive": True,  "deprecated": False, "notes": ["API schema"]},
    # ── Metrics ────────────────────────────────────────────────────────────────
    {"path": "/metrics",           "sensitive": True,  "deprecated": False, "notes": ["Prometheus metrics — leaks operational data"]},
    {"path": "/api/metrics",       "sensitive": True,  "deprecated": False, "notes": ["API metrics endpoint"]},
    {"path": "/prometheus",        "sensitive": True,  "deprecated": False, "notes": ["Prometheus scrape endpoint"]},
    # ── GraphQL ────────────────────────────────────────────────────────────────
    {"path": "/graphql",           "sensitive": True,  "deprecated": False, "notes": ["GraphQL endpoint"]},
    {"path": "/graphql/playground","sensitive": True,  "deprecated": False, "notes": ["GraphQL Playground IDE"]},
    {"path": "/graphiql",          "sensitive": True,  "deprecated": False, "notes": ["GraphiQL IDE"]},
    # ── Well-known / Discovery ─────────────────────────────────────────────────
    {"path": "/.well-known",                         "sensitive": False, "deprecated": False, "notes": ["Well-known directory"]},
    {"path": "/.well-known/openid-configuration",    "sensitive": False, "deprecated": False, "notes": ["OpenID Connect discovery"]},
    {"path": "/robots.txt",                          "sensitive": False, "deprecated": False, "notes": ["Robots exclusion file"]},
    {"path": "/sitemap.xml",                         "sensitive": False, "deprecated": False, "notes": ["Sitemap"]},
    # ── Admin ─────────────────────────────────────────────────────────────────
    {"path": "/admin",             "sensitive": True,  "deprecated": False, "notes": ["Admin panel"]},
    {"path": "/api/admin",         "sensitive": True,  "deprecated": False, "notes": ["Admin API"]},
    {"path": "/api/admin/config",  "sensitive": True,  "deprecated": False, "notes": ["Admin configuration — highly sensitive"]},
    {"path": "/api/admin/users",   "sensitive": True,  "deprecated": False, "notes": ["User management API"]},
    {"path": "/console",           "sensitive": True,  "deprecated": False, "notes": ["Console / management UI"]},
    # ── Management / Operations ────────────────────────────────────────────────
    {"path": "/management",         "sensitive": True,  "deprecated": False, "notes": ["Management interface"]},
    {"path": "/management/models",  "sensitive": True,  "deprecated": False, "notes": ["Model management — may allow model changes"]},
    {"path": "/management/team",    "sensitive": True,  "deprecated": False, "notes": ["Team management — user/permission control"]},
    {"path": "/management/keys",    "sensitive": True,  "deprecated": False, "notes": ["API key management"]},
    # ── API Keys / Secrets ────────────────────────────────────────────────────
    {"path": "/v1/key/generate",   "sensitive": True,  "deprecated": False, "notes": ["API key generation — critical"]},
    {"path": "/api/v1/apikey",     "sensitive": True,  "deprecated": False, "notes": ["API key management — critical"]},
    {"path": "/api/v1/credentials","sensitive": True,  "deprecated": False, "notes": ["Credentials endpoint — critical"]},
    # ── AI-Specific ───────────────────────────────────────────────────────────
    {"path": "/v1/chat/completions",    "sensitive": False, "deprecated": False, "notes": ["Chat completions (OpenAI-compatible)"]},
    {"path": "/v1/completions",         "sensitive": False, "deprecated": False, "notes": ["Text completions"]},
    {"path": "/v1/embeddings",          "sensitive": False, "deprecated": False, "notes": ["Embedding generation"]},
    {"path": "/v1/images/generations",  "sensitive": False, "deprecated": False, "notes": ["Image generation"]},
    {"path": "/api/generate",           "sensitive": False, "deprecated": False, "notes": ["Ollama generate"]},
    {"path": "/api/chat",               "sensitive": False, "deprecated": False, "notes": ["Ollama chat"]},
    {"path": "/api/embeddings",         "sensitive": False, "deprecated": False, "notes": ["Ollama embeddings"]},
    {"path": "/api/show",               "sensitive": True,  "deprecated": False, "notes": ["Model detail disclosure"]},
    {"path": "/api/pull",               "sensitive": True,  "deprecated": False, "notes": ["Model download — high impact"]},
    {"path": "/api/push",               "sensitive": True,  "deprecated": False, "notes": ["Model upload — critical"]},
    {"path": "/api/delete",             "sensitive": True,  "deprecated": False, "notes": ["Model deletion — critical"]},
    {"path": "/generate",               "sensitive": False, "deprecated": False, "notes": ["TGI generate endpoint"]},
    {"path": "/generate_stream",        "sensitive": False, "deprecated": False, "notes": ["TGI streaming generation"]},
    {"path": "/tokenize",               "sensitive": False, "deprecated": False, "notes": ["Tokenization endpoint"]},
    {"path": "/detokenize",             "sensitive": False, "deprecated": False, "notes": ["Detokenization endpoint"]},
    # ── Users / Auth ──────────────────────────────────────────────────────────
    {"path": "/api/users",         "sensitive": True,  "deprecated": False, "notes": ["User listing — PII disclosure risk"]},
    {"path": "/api/config",        "sensitive": True,  "deprecated": False, "notes": ["Service configuration"]},
    {"path": "/api/v1/config",     "sensitive": True,  "deprecated": False, "notes": ["API configuration"]},
    # ── Deprecated ────────────────────────────────────────────────────────────
    {"path": "/v0/models",          "sensitive": False, "deprecated": True,  "notes": ["Deprecated v0 API"]},
    {"path": "/api/v0/chatflows",   "sensitive": False, "deprecated": True,  "notes": ["Deprecated Flowise API"]},
    # ── Flowise-specific ──────────────────────────────────────────────────────
    {"path": "/api/v1/chatflows",  "sensitive": True,  "deprecated": False, "notes": ["Flowise chatflow listing"]},
    {"path": "/api/v1/tools",      "sensitive": True,  "deprecated": False, "notes": ["Flowise tool listing"]},
    {"path": "/api/v1/variables",  "sensitive": True,  "deprecated": False, "notes": ["Flowise variable listing"]},
    {"path": "/api/v1/stats",      "sensitive": False, "deprecated": False, "notes": ["Flowise statistics"]},
    # ── Dify-specific ─────────────────────────────────────────────────────────
    {"path": "/console/api/setup", "sensitive": True,  "deprecated": False, "notes": ["Dify setup endpoint"]},
    {"path": "/console/api/apps",  "sensitive": True,  "deprecated": False, "notes": ["Dify application listing"]},
    {"path": "/v1/datasets",       "sensitive": True,  "deprecated": False, "notes": ["RAG dataset listing"]},
    # ── LangGraph-specific ────────────────────────────────────────────────────
    {"path": "/graphs",            "sensitive": True,  "deprecated": False, "notes": ["LangGraph graph listing"]},
    {"path": "/threads",           "sensitive": True,  "deprecated": False, "notes": ["LangGraph thread listing"]},
    {"path": "/assistants",        "sensitive": True,  "deprecated": False, "notes": ["LangGraph assistant listing"]},
    # ── AnythingLLM-specific ──────────────────────────────────────────────────
    {"path": "/api/ping",          "sensitive": False, "deprecated": False, "notes": ["AnythingLLM ping"]},
    {"path": "/api/workspaces",    "sensitive": True,  "deprecated": False, "notes": ["AnythingLLM workspace listing"]},
    {"path": "/api/system-settings","sensitive": True, "deprecated": False, "notes": ["AnythingLLM system settings"]},
    {"path": "/api/system-vectors","sensitive": True,  "deprecated": False, "notes": ["AnythingLLM vector store"]},
    # ── Worker / Internal ─────────────────────────────────────────────────────
    {"path": "/worker_get_status",       "sensitive": True,  "deprecated": False, "notes": ["FastChat worker status"]},
    {"path": "/worker_get_model_details","sensitive": True,  "deprecated": False, "notes": ["FastChat model details"]},
    {"path": "/backend-monitor",         "sensitive": True,  "deprecated": False, "notes": ["LocalAI backend monitor"]},
    # ── MCP ───────────────────────────────────────────────────────────────────
    {"path": "/sse",               "sensitive": True,  "deprecated": False, "notes": ["MCP Server-Sent Events transport"]},
    {"path": "/mcp",               "sensitive": True,  "deprecated": False, "notes": ["MCP endpoint"]},
    {"path": "/mcp/sse",           "sensitive": True,  "deprecated": False, "notes": ["MCP SSE transport"]},
]

SENSITIVE_STATUS_CODES = {200, 206}
AUTH_STATUS_CODES = {401, 403}
NOT_FOUND_STATUS_CODES = {404, 410}


class EndpointEnumerationEngine:
    """
    Systematically enumerates AI platform endpoints.
    Each endpoint is characterised and integrated back into the AIService.
    """

    def __init__(
        self,
        timeout: float = 5.0,
        verify_ssl: bool = False,
        concurrency: int = 20,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.concurrency = concurrency

    async def enumerate(self, service: AIService) -> list[EndpointResult]:
        """
        Enumerate all known AI endpoints on the given service.
        Enriches the service's endpoint list and metadata in place.
        Returns the full list of EndpointResults.
        """
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            results = await self._probe_all(client, service.url)

        found = [r for r in results if r.exists]
        service.endpoints = list(
            dict.fromkeys(service.endpoints + [r.path for r in found])
        )

        sensitive = [r for r in found if r.sensitive and r.publicly_accessible]
        if sensitive:
            service.tags.append("sensitive-endpoints-exposed")
            service.metadata["sensitive_endpoints"] = [r.path for r in sensitive]

        unauthed_sensitive = [
            r for r in sensitive if not r.auth_required
        ]
        if unauthed_sensitive:
            service.tags.append("unauthenticated-sensitive-endpoints")
            service.metadata["unauthenticated_sensitive"] = [
                r.path for r in unauthed_sensitive
            ]

        deprecated = [r for r in found if r.deprecated]
        if deprecated:
            service.metadata["deprecated_endpoints"] = [r.path for r in deprecated]

        logger.info(
            f"Enumerated {service.host}:{service.port} — "
            f"{len(found)} active endpoints, "
            f"{len(sensitive)} sensitive, "
            f"{len(deprecated)} deprecated"
        )
        return results

    async def enumerate_many(
        self, services: list[AIService]
    ) -> dict[str, list[EndpointResult]]:
        """Enumerate multiple services concurrently."""
        results: dict[str, list[EndpointResult]] = {}
        tasks = {str(svc.id): self.enumerate(svc) for svc in services}
        for svc_id, coro in tasks.items():
            results[svc_id] = await coro
        return results

    async def _probe_all(
        self, client: httpx.AsyncClient, base_url: str
    ) -> list[EndpointResult]:
        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe(ep: dict[str, Any]) -> EndpointResult:
            async with semaphore:
                return await self._probe_endpoint(client, base_url, ep)

        return list(await asyncio.gather(*[probe(ep) for ep in COMMON_AI_ENDPOINTS]))

    async def _probe_endpoint(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        ep: dict[str, Any],
    ) -> EndpointResult:
        path: str = ep["path"]
        is_sensitive: bool = ep.get("sensitive", False)
        is_deprecated: bool = ep.get("deprecated", False)
        notes: list[str] = ep.get("notes", [])

        try:
            r = await client.get(f"{base_url}{path}", timeout=self.timeout)
            status_code = r.status_code
            content_type = r.headers.get("content-type", "")
            response_size = len(r.content)
            auth_required = status_code in AUTH_STATUS_CODES

            if status_code in NOT_FOUND_STATUS_CODES:
                endpoint_status = EndpointStatus.NOT_FOUND
            elif auth_required:
                endpoint_status = EndpointStatus.PROTECTED
            elif status_code == 200 and is_sensitive:
                endpoint_status = EndpointStatus.SENSITIVE
            elif status_code == 200:
                endpoint_status = EndpointStatus.UNPROTECTED
            elif status_code < 500:
                endpoint_status = EndpointStatus.EXISTS
            else:
                endpoint_status = EndpointStatus.NOT_FOUND

            if is_deprecated and endpoint_status != EndpointStatus.NOT_FOUND:
                endpoint_status = EndpointStatus.DEPRECATED

            return EndpointResult(
                path=path,
                http_status=status_code,
                status=endpoint_status,
                content_type=content_type,
                response_size=response_size,
                sensitive=is_sensitive,
                deprecated=is_deprecated,
                auth_required=auth_required,
                notes=notes,
            )

        except Exception:
            return EndpointResult(
                path=path,
                http_status=None,
                status=EndpointStatus.NOT_FOUND,
                sensitive=is_sensitive,
                deprecated=is_deprecated,
                notes=notes,
            )
