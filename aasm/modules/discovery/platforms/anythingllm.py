"""AnythingLLM Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class AnythingLLMDetector(BasePlatformDetector):
    platform_name = "AnythingLLM"
    service_type = AIServiceType.AI_WEB_UI
    default_ports = [3001, 8888, 3000]
    probe_paths = ["/api/ping", "/api/system-settings"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        ping_data = await self._probe_json(f"{base_url}/api/ping")
        if ping_data and ping_data.get("pong") is True:
            version = "unknown"
        else:
            r = await self._probe(f"{base_url}/")
            if r is None:
                return None
            html = r.text.lower()
            if "anythingllm" not in html and "anything-llm" not in html:
                return None
            version = "unknown"

        r = await self._probe(f"{base_url}/api/system-settings")
        auth_required = False
        auth_type = AuthType.NONE
        if r is not None:
            auth_required, auth_type = self._detect_auth(r)
            if r.status_code == 200:
                try:
                    data = r.json()
                    version = str(data.get("version", "unknown"))
                except Exception:
                    pass

        endpoints = [
            "/api/ping",
            "/api/system-settings",
            "/api/workspaces",
            "/api/users",
            "/api/system-vectors",
            "/api/admin/multi-user-mode",
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
            endpoints=endpoints,
            tags=["ai-web-ui", "anythingllm", "rag", "local-llm"],
        )
