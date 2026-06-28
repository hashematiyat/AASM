"""Text Generation Web UI (oobabooga) Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class TextGenWebUIDetector(BasePlatformDetector):
    platform_name = "Text Generation WebUI"
    service_type = AIServiceType.AI_WEB_UI
    default_ports = [7860, 5000, 7861]
    probe_paths = ["/api/v1/model", "/v1/models"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/")
        if r is None:
            return None

        html = r.text.lower()
        is_oobabooga = (
            "oobabooga" in html
            or "text generation web ui" in html
            or "text-generation-webui" in html
        )

        if not is_oobabooga:
            is_oobabooga = "gradio" in html and "model" in html

        model_data = await self._probe_json(f"{base_url}/api/v1/model")
        if model_data and isinstance(model_data, dict):
            if "model_name" in model_data or "lora_names" in model_data:
                is_oobabooga = True

        if not is_oobabooga:
            return None

        models: list[AIModel] = []
        v1_models = await self._probe_json(f"{base_url}/v1/models")
        if v1_models and "data" in v1_models:
            for m in v1_models["data"]:
                if isinstance(m, dict):
                    model_id = m.get("id", "unknown")
                    models.append(AIModel(id=model_id, name=model_id, raw=m))
        elif model_data and "model_name" in model_data:
            name = model_data["model_name"]
            if name and name != "None":
                models.append(AIModel(id=name, name=name, raw=model_data))

        r_api = await self._probe(f"{base_url}/api/v1/model")
        auth_required = False
        auth_type = AuthType.NONE
        if r_api is not None:
            auth_required, auth_type = self._detect_auth(r_api)

        endpoints = [
            "/api/v1/model",
            "/api/v1/generate",
            "/api/v1/chat",
            "/v1/models",
            "/v1/chat/completions",
            "/api/v1/token-count",
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
            tags=["ai-web-ui", "text-gen-webui", "oobabooga", "gradio", "local-llm"],
        )
