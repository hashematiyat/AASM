"""Hugging Face Text Generation Inference (TGI) Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class HuggingFaceTGIDetector(BasePlatformDetector):
    platform_name = "HuggingFace TGI"
    service_type = AIServiceType.LOCAL_LLM
    default_ports = [8080, 3000]
    probe_paths = ["/info", "/health"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        info = await self._probe_json(f"{base_url}/info")
        if not info or "model_id" not in info:
            return None

        model_id = info.get("model_id", "unknown")
        version = info.get("version", "unknown")

        models = [AIModel(
            id=model_id,
            name=model_id,
            raw=info,
        )]

        endpoints = ["/info", "/health", "/generate", "/generate_stream",
                     "/v1/chat/completions", "/v1/completions", "/metrics",
                     "/tokenize", "/decode"]

        return AIService(
            host=host,
            port=port,
            url=base_url,
            service_type=self.service_type,
            platform=self.platform_name,
            version=version,
            auth_required=False,
            auth_type=AuthType.NONE,
            models=models,
            endpoints=endpoints,
            tags=["local-llm", "huggingface", "tgi", "openai-compatible"],
        )
