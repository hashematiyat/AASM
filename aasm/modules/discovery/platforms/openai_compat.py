"""Generic OpenAI-compatible API Detector (fallback)."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class OpenAICompatDetector(BasePlatformDetector):
    platform_name = "OpenAI-Compatible API"
    service_type = AIServiceType.AI_API
    default_ports = [8000, 8080, 5000, 5001, 6000, 7000, 9000]
    probe_paths = ["/v1/models"]

    KNOWN_PLATFORMS = {
        "ollama": "Ollama",
        "lm studio": "LM Studio",
        "litellm": "LiteLLM",
        "vllm": "vLLM",
        "localai": "LocalAI",
        "jan": "Jan",
        "anything llm": "AnythingLLM",
    }

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/v1/models")
        if r is None:
            return None

        if r.status_code not in (200, 401, 403):
            return None

        auth_required, auth_type = self._detect_auth(r)

        platform = self.platform_name
        server_header = r.headers.get("server", "").lower()
        for key, name in self.KNOWN_PLATFORMS.items():
            if key in server_header:
                platform = name
                break

        models = []
        if r.status_code == 200:
            try:
                data = r.json()
                for m in data.get("data", []):
                    models.append(AIModel(
                        id=m.get("id", "unknown"),
                        name=m.get("id", "unknown"),
                        raw=m,
                    ))
            except Exception:
                pass

        if not models and r.status_code != 401:
            return None

        endpoints = ["/v1/models", "/v1/chat/completions",
                     "/v1/completions", "/v1/embeddings"]

        return AIService(
            host=host,
            port=port,
            url=base_url,
            service_type=self.service_type,
            platform=platform,
            version="unknown",
            auth_required=auth_required,
            auth_type=auth_type,
            models=models,
            endpoints=endpoints,
            tags=["openai-compatible", "api"],
        )
