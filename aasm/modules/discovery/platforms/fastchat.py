"""FastChat (LMSYS) Detector."""

from __future__ import annotations

from aasm.core.models import AIModel, AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class FastChatDetector(BasePlatformDetector):
    platform_name = "FastChat"
    service_type = AIServiceType.LOCAL_LLM
    default_ports = [8000, 21001, 21002, 7860]
    probe_paths = ["/v1/models", "/worker_get_status"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/v1/models")
        if r is None:
            return None

        is_fastchat = "fastchat" in r.headers.get("server", "").lower()

        models: list[AIModel] = []
        if r.status_code == 200:
            try:
                data = r.json()
                model_list = data.get("data", [])
                for m in model_list:
                    if isinstance(m, dict):
                        model_id = m.get("id", "unknown")
                        models.append(AIModel(id=model_id, name=model_id, raw=m))
            except Exception:
                pass

        if not is_fastchat:
            worker_data = await self._probe_json(f"{base_url}/worker_get_status")
            if worker_data and isinstance(worker_data, dict):
                if "model_names" in worker_data or "worker_addr" in worker_data:
                    is_fastchat = True
            else:
                if not models:
                    r_html = await self._probe(f"{base_url}/")
                    if r_html is None:
                        return None
                    html = r_html.text.lower()
                    if "fastchat" not in html and "vicuna" not in html:
                        return None
                    is_fastchat = True

        if not is_fastchat and not models:
            return None

        auth_required, auth_type = self._detect_auth(r)

        endpoints = [
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/worker_get_status",
            "/worker_get_model_details",
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
            tags=["local-llm", "fastchat", "openai-compatible", "vicuna", "lmsys"],
        )
