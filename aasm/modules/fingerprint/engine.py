"""
Module 2 — AI Fingerprinting Engine
Collects detailed technical information about discovered AI services.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from aasm.core.logger import get_logger
from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

logger = get_logger("fingerprint")

FINGERPRINT_ENDPOINTS: dict[str, list[str]] = {
    "Ollama": [
        "/api/version", "/api/tags", "/api/ps",
    ],
    "LiteLLM": [
        "/health", "/v1/models", "/v1/budget", "/management/models",
        "/management/team", "/v1/key/generate",
    ],
    "Flowise": [
        "/api/v1/chatflows", "/api/v1/tools", "/api/v1/credentials",
        "/api/v1/variables", "/api/v1/apikey",
    ],
    "Open WebUI": [
        "/api/version", "/api/config", "/api/models",
        "/api/users", "/api/admin/config",
    ],
    "default": [
        "/v1/models", "/v1/chat/completions", "/health",
        "/metrics", "/docs", "/redoc", "/openapi.json",
    ],
}

DANGEROUS_ENDPOINTS = {
    "/api/admin": "Admin interface exposed",
    "/api/admin/config": "Admin config exposed",
    "/management/models": "Model management API exposed",
    "/management/team": "Team management exposed",
    "/v1/key/generate": "API key generation endpoint exposed",
    "/api/v1/apikey": "API key management exposed",
    "/api/v1/credentials": "Credentials endpoint exposed",
    "/metrics": "Prometheus metrics exposed",
}


class FingerprintEngine:
    """
    Deep fingerprinting of discovered AI services.
    Enumerates endpoints, models, versions, and auth mechanisms.
    """

    def __init__(self, timeout: float = 10.0, verify_ssl: bool = False) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def fingerprint(self, service: AIService) -> AIService:
        """Enrich an AIService with detailed fingerprint information."""
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
        ) as client:
            enriched = await self._deep_fingerprint(client, service)
        return enriched

    async def fingerprint_many(self, services: list[AIService]) -> list[AIService]:
        """Fingerprint multiple services concurrently."""
        return list(await asyncio.gather(*[self.fingerprint(s) for s in services]))

    async def _deep_fingerprint(
        self, client: httpx.AsyncClient, service: AIService
    ) -> AIService:
        endpoints_to_probe = (
            FINGERPRINT_ENDPOINTS.get(service.platform or "", [])
            + FINGERPRINT_ENDPOINTS["default"]
        )

        discovered_endpoints: list[str] = list(service.endpoints)
        dangerous_found: list[str] = []

        async def probe(path: str) -> tuple[str, int | None]:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                return path, r.status_code
            except Exception:
                return path, None

        results = await asyncio.gather(*[probe(p) for p in endpoints_to_probe])

        for path, status in results:
            if status is not None and status < 500:
                if path not in discovered_endpoints:
                    discovered_endpoints.append(path)
                if path in DANGEROUS_ENDPOINTS and status in (200, 401, 403):
                    dangerous_found.append(path)

        service.endpoints = discovered_endpoints

        if dangerous_found:
            service.tags.append("dangerous-endpoints")
            service.metadata["dangerous_endpoints"] = dangerous_found

        await self._enrich_models(client, service)
        await self._detect_framework(client, service)

        logger.info(
            f"Fingerprinted {service.platform} @ {service.host}:{service.port} "
            f"— {len(discovered_endpoints)} endpoints"
        )
        return service

    async def _enrich_models(
        self, client: httpx.AsyncClient, service: AIService
    ) -> None:
        if service.models:
            return

        for path in ["/v1/models", "/api/tags"]:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200:
                    data = r.json()
                    models_raw = data.get("data", data.get("models", []))
                    for m in models_raw:
                        if isinstance(m, dict):
                            model_id = m.get("id", m.get("name", "unknown"))
                            service.models.append(AIModel(
                                id=model_id,
                                name=model_id,
                                raw=m,
                            ))
                    break
            except Exception:
                pass

    async def _detect_framework(
        self, client: httpx.AsyncClient, service: AIService
    ) -> None:
        """Probe /openapi.json or /docs to detect FastAPI/Flask/etc."""
        try:
            r = await client.get(f"{service.url}/openapi.json", timeout=3.0)
            if r.status_code == 200:
                data = r.json()
                info = data.get("info", {})
                title = info.get("title", "")
                version = info.get("version", "")
                service.metadata["openapi_title"] = title
                service.metadata["openapi_version"] = version
                service.tags.append("openapi-documented")
        except Exception:
            pass

        try:
            r = await client.get(f"{service.url}/metrics", timeout=3.0)
            if r.status_code == 200 and "# HELP" in r.text:
                service.tags.append("prometheus-metrics")
                service.metadata["has_metrics"] = True
        except Exception:
            pass
