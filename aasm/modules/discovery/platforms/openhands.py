"""OpenHands (formerly OpenDevin) AI Software Engineer Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class OpenHandsDetector(BasePlatformDetector):
    platform_name = "OpenHands"
    service_type = AIServiceType.AI_AGENT
    default_ports = [3000, 12000, 8080]
    probe_paths = ["/api/options", "/health"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/")
        if r is None:
            return None

        html = r.text.lower()
        is_openhands = (
            "openhands" in html
            or "opendevin" in html
            or "open-hands" in html
        )

        if not is_openhands:
            options_data = await self._probe_json(f"{base_url}/api/options")
            if options_data and isinstance(options_data, dict):
                if "provider" in options_data or "model" in options_data or "agent" in options_data:
                    is_openhands = True

        if not is_openhands:
            return None

        r_options = await self._probe(f"{base_url}/api/options")
        auth_required = False
        auth_type = AuthType.NONE
        version = "unknown"

        if r_options is not None:
            auth_required, auth_type = self._detect_auth(r_options)
            if r_options.status_code == 200:
                try:
                    data = r_options.json()
                    version = str(data.get("version", "unknown"))
                except Exception:
                    pass

        endpoints = [
            "/api/options",
            "/api/conversations",
            "/api/list-models",
            "/health",
            "/api/select-file",
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
            tags=["ai-agent", "openhands", "opendevin", "code-agent", "autonomous"],
        )
