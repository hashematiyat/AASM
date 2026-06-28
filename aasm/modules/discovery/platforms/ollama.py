"""Ollama LLM Server Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class OllamaDetector(BasePlatformDetector):
    platform_name = "Ollama"
    service_type = AIServiceType.LOCAL_LLM
    default_ports = [11434, 11435]
    probe_paths = ["/api/version", "/api/tags"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        version_data = await self._probe_json(f"{base_url}/api/version")
        if not version_data or "version" not in version_data:
            return None

        version = version_data.get("version", "unknown")
        models: list[AIModel] = []
        endpoints = ["/api/version", "/api/tags", "/api/generate", "/api/chat",
                     "/api/pull", "/api/push", "/api/embeddings", "/api/show"]

        tags_data = await self._probe_json(f"{base_url}/api/tags")
        if tags_data and "models" in tags_data:
            for m in tags_data["models"]:
                model = AIModel(
                    id=m.get("name", "unknown"),
                    name=m.get("name", "unknown"),
                    size=str(m.get("size", "")),
                    raw=m,
                )
                models.append(model)

        auth_required = False
        auth_type = AuthType.NONE
        r = await self._probe(f"{base_url}/api/tags")
        if r is not None:
            auth_required, auth_type = self._detect_auth(r)

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
            tags=["local-llm", "ollama", "openai-compatible"],
        )
