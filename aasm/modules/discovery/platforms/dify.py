"""Dify AI Application Platform Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class DifyDetector(BasePlatformDetector):
    platform_name = "Dify"
    service_type = AIServiceType.AI_AGENT
    default_ports = [3000, 80, 8080, 5001]
    probe_paths = ["/api/version", "/console/api/setup", "/v1/info"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        version_data = await self._probe_json(f"{base_url}/api/version")
        if version_data and "version" in version_data:
            pass
        else:
            setup_data = await self._probe_json(f"{base_url}/console/api/setup")
            if setup_data is None:
                info_data = await self._probe_json(f"{base_url}/v1/info")
                if info_data is None:
                    r = await self._probe(f"{base_url}/")
                    if r is None:
                        return None
                    html = r.text.lower()
                    if "dify" not in html:
                        return None
                    version_data = {}
                else:
                    version_data = info_data
            else:
                version_data = setup_data

        r = await self._probe(f"{base_url}/console/api/apps")
        auth_required = False
        auth_type = AuthType.NONE
        if r is not None:
            auth_required, auth_type = self._detect_auth(r)
            if r.status_code not in (200, 401, 403):
                if not version_data:
                    return None

        version = "unknown"
        if isinstance(version_data, dict):
            version = version_data.get("version", version_data.get("dify_version", "unknown"))

        endpoints = [
            "/api/version",
            "/console/api/setup",
            "/console/api/apps",
            "/v1/chat-messages",
            "/v1/workflows/run",
            "/v1/datasets",
            "/v1/info",
            "/v1/messages",
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
            tags=["ai-agent", "dify", "rag", "workflow", "low-code"],
        )
