"""OpenRouter AI Gateway Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class OpenRouterDetector(BasePlatformDetector):
    platform_name = "OpenRouter"
    service_type = AIServiceType.AI_GATEWAY
    default_ports = [443, 8080, 3000]
    probe_paths = ["/api/v1/models", "/v1/models"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/api/v1/models")
        if r is None:
            r = await self._probe(f"{base_url}/v1/models")
            if r is None:
                return None

        is_openrouter = (
            "openrouter" in r.headers.get("server", "").lower()
            or "openrouter" in r.headers.get("x-openrouter-version", "").lower()
        )

        models: list[AIModel] = []
        if r.status_code == 200:
            try:
                data = r.json()
                model_list = data.get("data", [])
                for m in model_list[:20]:
                    if isinstance(m, dict):
                        model_id = m.get("id", "unknown")
                        models.append(AIModel(
                            id=model_id,
                            name=m.get("name", model_id),
                            raw=m,
                        ))

                if model_list and not is_openrouter:
                    first = model_list[0] if model_list else {}
                    if "pricing" in first or "top_provider" in first:
                        is_openrouter = True

            except Exception:
                pass

        if not is_openrouter:
            return None

        auth_required, auth_type = self._detect_auth(r)

        endpoints = [
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/generation",
            "/v1/models",
            "/v1/chat/completions",
        ]

        return AIService(
            host=host,
            port=port,
            url=base_url,
            service_type=self.service_type,
            platform=self.platform_name,
            version="unknown",
            auth_required=auth_required,
            auth_type=auth_type,
            models=models,
            endpoints=endpoints,
            tags=["ai-gateway", "openrouter", "openai-compatible", "multi-model"],
        )
