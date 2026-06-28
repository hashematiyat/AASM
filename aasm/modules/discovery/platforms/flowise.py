"""Flowise AI Agent Builder Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class FlowiseDetector(BasePlatformDetector):
    platform_name = "Flowise"
    service_type = AIServiceType.AI_AGENT
    default_ports = [3000, 3001]
    probe_paths = ["/api/v1/chatflows", "/api/v1/tools"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/api/v1/chatflows")
        if r is None:
            return None

        if r.status_code not in (200, 401, 403):
            return None

        auth_required = r.status_code in (401, 403)
        auth_type = AuthType.BEARER_TOKEN if auth_required else AuthType.NONE

        endpoints = ["/api/v1/chatflows", "/api/v1/tools", "/api/v1/credentials",
                     "/api/v1/variables", "/api/v1/stats", "/api/v1/prediction"]

        version = "unknown"
        version_data = await self._probe_json(f"{base_url}/api/v1/version")
        if version_data:
            version = version_data.get("version", "unknown")

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
            tags=["ai-agent", "flowise", "langchain", "low-code"],
        )
