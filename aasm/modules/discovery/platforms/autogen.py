"""Microsoft AutoGen Agent Framework Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class AutoGenDetector(BasePlatformDetector):
    platform_name = "AutoGen"
    service_type = AIServiceType.AI_AGENT
    default_ports = [8081, 8000, 8080, 3000]
    probe_paths = ["/api/health", "/health"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/")
        if r is None:
            return None

        html = r.text.lower()
        if "autogen" not in html and "microsoft/autogen" not in html:
            r2 = await self._probe(f"{base_url}/api/agents")
            if r2 is None or r2.status_code not in (200, 401, 403):
                return None
            if r2.status_code == 200:
                try:
                    data = r2.json()
                    if "agents" not in data and "groupchat" not in data:
                        return None
                except Exception:
                    return None

        auth_required = False
        auth_type = AuthType.NONE
        version = "unknown"

        r_health = await self._probe(f"{base_url}/api/health")
        if r_health is not None:
            auth_required, auth_type = self._detect_auth(r_health)
            if r_health.status_code == 200:
                try:
                    data = r_health.json()
                    version = str(data.get("version", "unknown"))
                except Exception:
                    pass

        endpoints = [
            "/api/agents",
            "/api/conversations",
            "/api/health",
            "/health",
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
            tags=["ai-agent", "autogen", "microsoft", "multi-agent"],
        )
