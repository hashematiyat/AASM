"""LocalAI Server Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class LocalAIDetector(BasePlatformDetector):
    platform_name = "LocalAI"
    service_type = AIServiceType.LOCAL_LLM
    default_ports = [8080, 8000, 9000]
    probe_paths = ["/v1/models", "/models"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/v1/models")
        if r is None:
            return None

        is_localai = (
            "localai" in r.headers.get("server", "").lower()
            or "localai" in r.headers.get("x-localai-version", "").lower()
        )

        models_data = None
        if r.status_code == 200:
            try:
                models_data = r.json()
            except Exception:
                pass

        if not is_localai:
            backend_r = await self._probe(f"{base_url}/backend-monitor")
            if backend_r is None or backend_r.status_code not in (200, 401, 403):
                gallery_data = await self._probe_json(f"{base_url}/models/gallery")
                if gallery_data is None:
                    if models_data is None:
                        return None

        models: list[AIModel] = []
        if models_data and "data" in models_data:
            for m in models_data["data"]:
                if isinstance(m, dict):
                    model_id = m.get("id", "unknown")
                    models.append(AIModel(id=model_id, name=model_id, raw=m))

        version = "unknown"
        version_header = r.headers.get("x-localai-version", "")
        if version_header:
            version = version_header

        auth_required, auth_type = self._detect_auth(r)

        endpoints = [
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/images/generations",
            "/v1/audio/transcriptions",
            "/models",
            "/backend-monitor",
        ]

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
            tags=["local-llm", "localai", "openai-compatible", "multi-modal"],
        )
