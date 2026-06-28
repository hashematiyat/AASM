"""vLLM Server Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class VLLMDetector(BasePlatformDetector):
    platform_name = "vLLM"
    service_type = AIServiceType.LOCAL_LLM
    default_ports = [8000, 8080]
    probe_paths = ["/v1/models", "/health"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/v1/models")
        if r is None:
            return None

        is_vllm = "vllm" in r.headers.get("server", "").lower()
        if not is_vllm:
            health = await self._probe_json(f"{base_url}/health")
            if health is None:
                return None

        models_data = await self._probe_json(f"{base_url}/v1/models")
        models = []
        if models_data and "data" in models_data:
            for m in models_data["data"]:
                models.append(AIModel(
                    id=m.get("id", ""),
                    name=m.get("id", ""),
                    raw=m,
                ))
            if not models:
                return None

        endpoints = ["/v1/models", "/v1/chat/completions", "/v1/completions",
                     "/v1/embeddings", "/health", "/metrics"]

        return AIService(
            host=host,
            port=port,
            url=base_url,
            service_type=self.service_type,
            platform=self.platform_name,
            version="unknown",
            auth_required=False,
            auth_type=AuthType.NONE,
            models=models,
            endpoints=endpoints,
            tags=["local-llm", "vllm", "openai-compatible", "gpu"],
        )
