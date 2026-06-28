"""LangGraph Server Detector."""

from __future__ import annotations

from aasm.core.models import AIService, AIServiceType, AuthType

from .base import BasePlatformDetector


class LangGraphDetector(BasePlatformDetector):
    platform_name = "LangGraph"
    service_type = AIServiceType.AI_AGENT
    default_ports = [8123, 8000, 8080]
    probe_paths = ["/ok", "/graphs"]

    async def detect(self, host: str, port: int) -> AIService | None:
        base_url = self._build_url(host, port)

        r = await self._probe(f"{base_url}/ok")
        if r is not None and r.status_code == 200:
            body = r.text.strip().lower()
            if body == "ok":
                is_langgraph = True
            else:
                is_langgraph = False
        else:
            is_langgraph = False

        if not is_langgraph:
            graphs_data = await self._probe_json(f"{base_url}/graphs")
            if graphs_data is None:
                return None
            is_langgraph = isinstance(graphs_data, (list, dict))

        if not is_langgraph:
            return None

        r_graphs = await self._probe(f"{base_url}/graphs")
        auth_required = False
        auth_type = AuthType.NONE
        if r_graphs is not None:
            auth_required, auth_type = self._detect_auth(r_graphs)

        version_data = await self._probe_json(f"{base_url}/version")
        version = "unknown"
        if version_data and isinstance(version_data, dict):
            version = str(version_data.get("version", "unknown"))

        endpoints = [
            "/ok",
            "/graphs",
            "/threads",
            "/assistants",
            "/runs",
            "/store",
            "/version",
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
            tags=["ai-agent", "langgraph", "langchain", "stateful", "graph"],
        )
