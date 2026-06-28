"""
Module 6 — AI Attack Surface Mapper
Builds the AI asset inventory and relationship graph.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

from aasm.core.logger import get_logger
from aasm.core.models import (
    AIAgent,
    AIService,
    AIServiceType,
    AttackPath,
    MCPServer,
    ScanResult,
    SecurityFinding,
    Severity,
)

logger = get_logger("mapper")


class AttackSurfaceMapper:
    """
    Builds the AI attack surface graph and discovers attack paths.
    """

    def __init__(self) -> None:
        self.graph = nx.DiGraph() if HAS_NETWORKX else None

    def build(self, result: ScanResult) -> ScanResult:
        """Build attack surface map from scan result."""
        self._build_graph(result)
        result.attack_paths = self._discover_attack_paths(result)
        logger.info(
            f"Attack surface mapped: {len(result.services)} services, "
            f"{len(result.attack_paths)} attack paths"
        )
        return result

    def _build_graph(self, result: ScanResult) -> None:
        if not self.graph:
            return

        for svc in result.services:
            self.graph.add_node(
                str(svc.id),
                type="service",
                label=svc.display_name,
                platform=svc.platform,
                host=svc.host,
                port=svc.port,
                auth_required=svc.auth_required,
            )

        for mcp in result.mcp_servers:
            svc_id = str(mcp.service.id)
            self.graph.add_node(
                str(mcp.id),
                type="mcp_server",
                label=mcp.server_name or f"MCP@{mcp.service.host}",
                tool_count=len(mcp.tools),
                dangerous_tools=mcp.dangerous_tools,
            )
            self.graph.add_edge(svc_id, str(mcp.id), relation="hosts")

        for agent in result.agents:
            self.graph.add_node(
                str(agent.id),
                type="agent",
                label=agent.agent_name,
                framework=agent.framework,
                capabilities=[c.value for c in agent.capabilities],
            )
            for mcp_id in agent.connected_mcp_servers:
                self.graph.add_edge(str(agent.id), mcp_id, relation="uses_mcp")

    def _discover_attack_paths(self, result: ScanResult) -> list[AttackPath]:
        paths: list[AttackPath] = []

        unauthenticated = [s for s in result.services if not s.auth_required]
        if unauthenticated:
            for svc in unauthenticated:
                if svc.models:
                    paths.append(AttackPath(
                        name="Unauthenticated LLM Access",
                        description=(
                            f"Attacker can directly access {svc.platform} at "
                            f"{svc.url} without authentication and query any loaded model."
                        ),
                        steps=[
                            f"Identify {svc.platform} at {svc.url}",
                            "No authentication required — direct API access",
                            "Query models via /v1/chat/completions or equivalent",
                            "Exfiltrate data, test for prompt injection, abuse model capabilities",
                        ],
                        severity=Severity.CRITICAL,
                        assets_involved=[svc.id],
                        entry_point=svc.url,
                        impact="Data exfiltration, prompt injection, model abuse, cost incurrence",
                        likelihood=0.95,
                    ))

        for mcp in result.mcp_servers:
            dangerous = [t for t in mcp.tools if t.dangerous]
            if dangerous and not mcp.auth_required:
                paths.append(AttackPath(
                    name=f"Unauthenticated MCP Tool Abuse — {mcp.server_name or mcp.service.host}",
                    description=(
                        "An attacker can call dangerous MCP tools directly "
                        "without authentication, enabling code execution or system access."
                    ),
                    steps=[
                        f"Access MCP server at {mcp.service.url}",
                        "Enumerate tools via tools/list (no auth required)",
                        f"Call dangerous tool: {dangerous[0].name}",
                        "Achieve code execution, file access, or lateral movement",
                    ],
                    severity=Severity.CRITICAL,
                    assets_involved=[mcp.id],
                    entry_point=mcp.service.url,
                    impact="Remote code execution, data exfiltration, privilege escalation",
                    likelihood=0.90,
                ))

        for mcp in result.mcp_servers:
            for agent in result.agents:
                if str(mcp.id) in agent.connected_mcp_servers:
                    if mcp.dangerous_tools:
                        paths.append(AttackPath(
                            name=f"Prompt Injection → Agent → Dangerous MCP Tool",
                            description=(
                                f"An attacker injects a malicious prompt into the agent "
                                f"'{agent.agent_name}', causing it to invoke the dangerous "
                                f"MCP tool '{mcp.dangerous_tools[0]}' on the attacker's behalf."
                            ),
                            steps=[
                                f"Craft prompt injection targeting {agent.agent_name}",
                                "Agent processes malicious instruction",
                                f"Agent calls MCP tool: {mcp.dangerous_tools[0]}",
                                "Attacker achieves indirect code execution or data access",
                            ],
                            severity=Severity.CRITICAL,
                            assets_involved=[agent.id, mcp.id],
                            entry_point=agent.service.url,
                            impact="Indirect code execution through trusted agent context",
                            likelihood=0.75,
                        ))

        return paths

    def get_graph_data(self) -> dict[str, Any]:
        if not self.graph:
            return {"nodes": [], "edges": []}
        return {
            "nodes": [
                {"id": n, **self.graph.nodes[n]}
                for n in self.graph.nodes
            ],
            "edges": [
                {"source": u, "target": v, **self.graph.edges[u, v]}
                for u, v in self.graph.edges
            ],
        }

    def to_dot(self) -> str:
        if not self.graph:
            return "digraph { }"
        try:
            from networkx.drawing.nx_agraph import to_agraph
            A = to_agraph(self.graph)
            return str(A)
        except Exception:
            lines = ["digraph AASM {", '  rankdir=LR;']
            for node, data in self.graph.nodes(data=True):
                label = data.get("label", node)
                shape = "box" if data.get("type") == "mcp_server" else "ellipse"
                lines.append(f'  "{node}" [label="{label}" shape="{shape}"];')
            for u, v, data in self.graph.edges(data=True):
                rel = data.get("relation", "")
                lines.append(f'  "{u}" -> "{v}" [label="{rel}"];')
            lines.append("}")
            return "\n".join(lines)

    def to_mermaid(self, result: ScanResult) -> str:
        lines = ["graph LR"]
        for svc in result.services:
            safe_id = f"svc_{str(svc.id).replace('-', '_')[:8]}"
            lines.append(f'  {safe_id}["{svc.platform} @ {svc.host}:{svc.port}"]')
        for mcp in result.mcp_servers:
            safe_id = f"mcp_{str(mcp.id).replace('-', '_')[:8]}"
            lines.append(f'  {safe_id}(("{mcp.server_name or "MCP Server"}"))')
        for agent in result.agents:
            safe_id = f"agt_{str(agent.id).replace('-', '_')[:8]}"
            lines.append(f'  {safe_id}{{{agent.agent_name or "AI Agent"}}}')
        return "\n".join(lines)
