"""Langflow Visual AI Pipeline Builder Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class LangflowDetector(BasePlatformDetector):
    platform_name = "Langflow"
    service_type = AIServiceType.AI_AGENT
    default_ports = [7860, 7861, 3000, 8080]
    probe_paths = ["/api/v1/version", "/health"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        version_data = await self._probe_json(f"{base_url}/api/v1/version")
        if version_data and "version" in version_data:
            version = str(version_data.get("version", "unknown"))
        else:
            health_data = await self._probe_json(f"{base_url}/health")
            if health_data is None:
                r = await self._probe(f"{base_url}/")
                if r is None:
                    return None
                html = r.text.lower()
                if "langflow" not in html:
                    return None
                version = "unknown"
                version_data = {}
            else:
                version = "unknown"
                version_data = health_data

        r = await self._probe(f"{base_url}/api/v1/flows")
        auth_required = False
        auth_type = AuthType.NONE
        if r is not None:
            auth_required, auth_type = self._detect_auth(r)

        endpoints = [
            "/api/v1/version",
            "/api/v1/flows",
            "/api/v1/components",
            "/api/v1/config",
            "/health",
            "/api/v1/run",
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
            tags=["ai-agent", "langflow", "langchain", "visual", "pipeline"],
        )
