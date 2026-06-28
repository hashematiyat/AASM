"""LiteLLM Proxy Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class LiteLLMDetector(BasePlatformDetector):
    platform_name = "LiteLLM"
    service_type = AIServiceType.AI_GATEWAY
    default_ports = [4000, 8000, 8080]
    probe_paths = ["/health", "/v1/models"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        health = await self._probe_json(f"{base_url}/health")
        if not health:
            return None

        is_litellm = (
            "litellm_version" in health
            or health.get("status") == "healthy"
            or "router" in str(health).lower()
        )
        if not is_litellm:
            return None

        version = health.get("litellm_version", "unknown")
        models = []
        models_data = await self._probe_json(f"{base_url}/v1/models")
        if models_data and "data" in models_data:
            for m in models_data["data"]:
                models.append(AIModel(
                    id=m.get("id", "unknown"),
                    name=m.get("id", "unknown"),
                    raw=m,
                ))

        auth_required = False
        auth_type = AuthType.NONE
        r = await self._probe(f"{base_url}/v1/chat/completions")
        if r and r.status_code == 401:
            auth_required = True
            auth_type = AuthType.API_KEY

        endpoints = ["/health", "/v1/models", "/v1/chat/completions",
                     "/v1/completions", "/v1/embeddings", "/v1/budget",
                     "/v1/key/generate", "/management/models"]

        return AIService(
            host=host,
            port=port,
            url=base_url,
            service_type=self.service_type,
            platform=self.platform_name,
            version=version,
            auth_required=auth_required,
            auth_type=auth_type,
            models=models,
            endpoints=endpoints,
            tags=["ai-gateway", "litellm", "openai-compatible", "proxy"],
        )
