"""
Module 3 — MCP Discovery Scanner
Discovers and enumerates Model Context Protocol servers.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from aasm.core.logger import get_logger
from aasm.core.models import (
    AIService,
    AIServiceType,
    AuthType,
    MCPPrompt,
    MCPResource,
    MCPServer,
    MCPTool,
)

logger = get_logger("mcp.scanner")

MCP_DEFAULT_PORTS = [3000, 8080, 8000, 5000, 4000, 7000, 9000, 3001]

DANGEROUS_TOOL_PATTERNS = {
    "bash": "Direct shell execution",
    "shell": "Shell command execution",
    "exec": "Command execution",
    "run_command": "Command execution",
    "docker": "Docker daemon access",
    "kubectl": "Kubernetes access",
    "file_write": "Filesystem write access",
    "write_file": "Filesystem write access",
    "delete_file": "Filesystem delete",
    "git_push": "Git repository write",
    "send_email": "Email sending capability",
    "database_query": "Database query access",
    "sql": "SQL execution",
    "http_request": "Arbitrary HTTP requests",
    "fetch": "External HTTP fetch",
    "github_": "GitHub API access",
    "aws_": "AWS API access",
    "gcp_": "GCP API access",
    "azure_": "Azure API access",
}


class MCPScanner:
    """
    Discovers MCP servers by probing known ports and endpoints.
    Enumerates tools, resources, and prompts via JSON-RPC 2.0.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
        ports: list[int] | None = None,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.ports = ports or MCP_DEFAULT_PORTS

    async def scan_host(self, host: str) -> list[MCPServer]:
        """Scan a host for MCP servers across default ports."""
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
        ) as client:
            tasks = [self._probe_port(client, host, port) for port in self.ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [r for r in results if isinstance(r, MCPServer)]

    async def scan_url(self, url: str) -> MCPServer | None:
        """Scan a specific URL for an MCP server."""
        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
        ) as client:
            return await self._probe_url(client, url)

    async def _probe_port(
        self, client: httpx.AsyncClient, host: str, port: int
    ) -> MCPServer | None:
        for scheme in ["http", "https"] if port in (443, 8443) else ["http"]:
            url = f"{scheme}://{host}:{port}"
            result = await self._probe_url(client, url)
            if result:
                return result
        return None

    async def _probe_url(
        self, client: httpx.AsyncClient, base_url: str
    ) -> MCPServer | None:
        """Probe a URL to detect and enumerate an MCP server."""
        mcp_endpoints = ["/mcp", "/", "/api/mcp", "/sse", "/messages"]

        for endpoint in mcp_endpoints:
            url = f"{base_url}{endpoint}"
            try:
                payload = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "aasm-scanner", "version": "0.1.0"},
                    },
                }
                r = await client.post(
                    url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                    timeout=5.0,
                )

                if r.status_code == 200:
                    try:
                        data = r.json()
                        if "result" in data or "id" in data:
                            return await self._build_mcp_server(client, base_url, endpoint, data)
                    except Exception:
                        pass

                if r.status_code == 401:
                    svc = AIService(
                        host=base_url.split("://")[1].split(":")[0],
                        port=int(base_url.split(":")[-1]) if ":" in base_url else 80,
                        url=base_url,
                        service_type=AIServiceType.MCP_SERVER,
                        auth_required=True,
                        auth_type=AuthType.UNKNOWN,
                    )
                    return MCPServer(service=svc, auth_required=True)

            except Exception:
                continue

        return None

    async def _build_mcp_server(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str,
        init_response: dict[str, Any],
    ) -> MCPServer:
        result = init_response.get("result", {})
        server_info = result.get("serverInfo", {})
        capabilities = result.get("capabilities", {})

        host_part = base_url.split("://")[-1]
        host = host_part.split(":")[0]
        try:
            port = int(host_part.split(":")[1]) if ":" in host_part else 80
        except (IndexError, ValueError):
            port = 80

        service = AIService(
            host=host,
            port=port,
            url=base_url,
            service_type=AIServiceType.MCP_SERVER,
            platform="MCP Server",
            version=server_info.get("version", "unknown"),
        )

        server = MCPServer(
            service=service,
            server_name=server_info.get("name"),
            protocol_version=result.get("protocolVersion"),
            auth_required=False,
        )

        mcp_base = f"{base_url}{endpoint}"

        if "tools" in capabilities:
            server.tools = await self._list_tools(client, mcp_base)

        if "resources" in capabilities:
            server.resources = await self._list_resources(client, mcp_base)

        if "prompts" in capabilities:
            server.prompts = await self._list_prompts(client, mcp_base)

        server.dangerous_tools = [
            t.name for t in server.tools if t.dangerous
        ]

        logger.info(
            f"[+] MCP Server: {server.server_name or host}:{port} "
            f"— {len(server.tools)} tools, {len(server.resources)} resources"
        )
        return server

    async def _list_tools(
        self, client: httpx.AsyncClient, url: str
    ) -> list[MCPTool]:
        try:
            r = await client.post(
                url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                timeout=5.0,
            )
            if r.status_code != 200:
                return []
            data = r.json()
            tools = []
            for t in data.get("result", {}).get("tools", []):
                dangerous, reasons = self._check_dangerous_tool(t.get("name", ""))
                tools.append(MCPTool(
                    name=t.get("name", ""),
                    description=t.get("description"),
                    parameters=t.get("inputSchema", {}),
                    dangerous=dangerous,
                    risk_reasons=reasons,
                ))
            return tools
        except Exception:
            return []

    async def _list_resources(
        self, client: httpx.AsyncClient, url: str
    ) -> list[MCPResource]:
        try:
            r = await client.post(
                url,
                json={"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
                timeout=5.0,
            )
            if r.status_code != 200:
                return []
            data = r.json()
            return [
                MCPResource(
                    uri=res.get("uri", ""),
                    name=res.get("name"),
                    mime_type=res.get("mimeType"),
                    description=res.get("description"),
                )
                for res in data.get("result", {}).get("resources", [])
            ]
        except Exception:
            return []

    async def _list_prompts(
        self, client: httpx.AsyncClient, url: str
    ) -> list[MCPPrompt]:
        try:
            r = await client.post(
                url,
                json={"jsonrpc": "2.0", "id": 4, "method": "prompts/list"},
                timeout=5.0,
            )
            if r.status_code != 200:
                return []
            data = r.json()
            return [
                MCPPrompt(
                    name=p.get("name", ""),
                    description=p.get("description"),
                    arguments=p.get("arguments", []),
                )
                for p in data.get("result", {}).get("prompts", [])
            ]
        except Exception:
            return []

    def _check_dangerous_tool(self, name: str) -> tuple[bool, list[str]]:
        name_lower = name.lower()
        reasons = []
        for pattern, reason in DANGEROUS_TOOL_PATTERNS.items():
            if pattern in name_lower:
                reasons.append(reason)
        return bool(reasons), reasons
