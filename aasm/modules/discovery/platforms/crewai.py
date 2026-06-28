"""CrewAI Agent Framework Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class CrewAIDetector(BasePlatformDetector):
    platform_name = "CrewAI"
    service_type = AIServiceType.AI_AGENT
    default_ports = [8000, 8080, 3000]
    probe_paths = ["/api/health", "/api/crews", "/health"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        is_crewai = False

        r = await self._probe(f"{base_url}/api/crews")
        if r is not None and r.status_code in (200, 401, 403):
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "crews" in data or "agents" in data or "tasks" in data:
                        is_crewai = True
                except Exception:
                    pass
            else:
                is_crewai = True

        if not is_crewai:
            r = await self._probe(f"{base_url}/")
            if r is None:
                return None
            html = r.text.lower()
            if "crewai" not in html:
                return None
            is_crewai = True

        r_health = await self._probe(f"{base_url}/api/health")
        auth_required = False
        auth_type = AuthType.NONE
        version = "unknown"
        if r_health is not None:
            auth_required, auth_type = self._detect_auth(r_health)
            if r_health.status_code == 200:
                try:
                    data = r_health.json()
                    version = str(data.get("version", "unknown"))
                except Exception:
                    pass

        endpoints = [
            "/api/crews",
            "/api/agents",
            "/api/tasks",
            "/api/health",
            "/health",
            "/api/run",
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
            tags=["ai-agent", "crewai", "multi-agent", "autonomous"],
        )
