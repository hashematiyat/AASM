"""Open WebUI Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class OpenWebUIDetector(BasePlatformDetector):
    platform_name = "Open WebUI"
    service_type = AIServiceType.AI_WEB_UI
    default_ports = [3000, 8080]
    probe_paths = ["/api/version", "/api/config"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        version_data = await self._probe_json(f"{base_url}/api/version")
        if not version_data:
            return None

        if "version" not in version_data and "name" not in version_data:
            title_check = await self._probe(f"{base_url}/")
            if title_check is None or "open-webui" not in title_check.text.lower():
                return None

        version = version_data.get("version", "unknown")
        endpoints = ["/api/version", "/api/config", "/api/models",
                     "/api/chat/completions", "/api/users"]

        auth_required = False
        auth_type = AuthType.NONE
        models_resp = await self._probe(f"{base_url}/api/models")
        if models_resp is not None:
            auth_required, auth_type = self._detect_auth(models_resp)
            if models_resp.status_code == 401:
                auth_required = True
                auth_type = AuthType.BEARER_TOKEN

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
            tags=["web-ui", "open-webui"],
        )
