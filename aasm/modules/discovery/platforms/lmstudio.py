"""LM Studio Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class LMStudioDetector(BasePlatformDetector):
    platform_name = "LM Studio"
    service_type = AIServiceType.LOCAL_LLM
    default_ports = [1234, 1235]
    probe_paths = ["/v1/models", "/v1/chat/completions"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        models_data = await self._probe_json(f"{base_url}/v1/models")
        if not models_data or "data" not in models_data:
            return None

        server_header = ""
        r = await self._probe(f"{base_url}/v1/models")
        if r:
            server_header = r.headers.get("server", "").lower()
            if "lm-studio" not in server_header and "lmstudio" not in server_header:
                x_provider = r.headers.get("x-provider", "").lower()
                if "lm-studio" not in x_provider and "lmstudio" not in x_provider:
                    pass

        models = []
        for m in models_data.get("data", []):
            models.append(AIModel(
                id=m.get("id", "unknown"),
                name=m.get("id", "unknown"),
                raw=m,
            ))

        endpoints = ["/v1/models", "/v1/chat/completions",
                     "/v1/completions", "/v1/embeddings"]

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
            tags=["local-llm", "lmstudio", "openai-compatible"],
        )
