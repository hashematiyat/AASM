"""
Module 9 — Visualization Engine
Generates AI infrastructure graphs and diagrams.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aasm.core.logger import get_logger
from aasm.core.models import ScanResult

logger = get_logger("visualization")


class VisualizationEngine:
    """Generates infrastructure graphs in multiple formats."""

    def __init__(self, output_dir: str = "./aasm_reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        result: ScanResult,
        formats: list[str] | None = None,
    ) -> dict[str, Path]:
        formats = formats or ["dot", "mermaid"]
        outputs: dict[str, Path] = {}
        stem = f"aasm_graph_{result.target.replace('/', '_')}"

        if "dot" in formats:
            p = self.output_dir / f"{stem}.dot"
            dot_content = self._to_dot(result)
            p.write_text(dot_content)
            outputs["dot"] = p

        if "mermaid" in formats:
            p = self.output_dir / f"{stem}.md"
            mermaid = self._to_mermaid(result)
            p.write_text(mermaid)
            outputs["mermaid"] = p

        if "svg" in formats:
            dot_path = outputs.get("dot")
            if dot_path:
                svg_path = self._dot_to_svg(dot_path)
                if svg_path:
                    outputs["svg"] = svg_path

        logger.info(f"Graphs generated: {list(outputs.keys())}")
        return outputs

    def _to_dot(self, result: ScanResult) -> str:
        lines = [
            'digraph "AASM_Attack_Surface" {',
            '  rankdir=LR;',
            '  node [fontname="Helvetica" fontsize=11];',
            '  edge [fontsize=9];',
            '  graph [bgcolor="#0f1117" fontcolor="white"];',
            "",
            '  subgraph cluster_services {',
            '    label="AI Services"; style=filled; fillcolor="#161b22";',
            '    color="#58a6ff"; fontcolor="#58a6ff";',
        ]
        for svc in result.services:
            node_id = f"svc_{str(svc.id).replace('-', '')[:12]}"
            color = "#ff4444" if not svc.auth_required else "#28a745"
            label = f"{svc.platform or 'AI Service'}\\n{svc.host}:{svc.port}"
            lines.append(
                f'    {node_id} [label="{label}" style=filled fillcolor="{color}" '
                f'fontcolor="white" shape=box];'
            )
        lines.append("  }")

        if result.mcp_servers:
            lines.append("")
            lines.append('  subgraph cluster_mcp {')
            lines.append('    label="MCP Servers"; style=filled; fillcolor="#1a1f2e";')
            lines.append('    color="#ff6b35"; fontcolor="#ff6b35";')
            for mcp in result.mcp_servers:
                node_id = f"mcp_{str(mcp.id).replace('-', '')[:12]}"
                color = "#ff0000" if mcp.dangerous_tools else "#f0ad4e"
                label = f"{mcp.server_name or 'MCP Server'}\\n{len(mcp.tools)} tools"
                if mcp.dangerous_tools:
                    label += f"\\n⚠ {len(mcp.dangerous_tools)} dangerous"
                lines.append(
                    f'    {node_id} [label="{label}" style=filled fillcolor="{color}" '
                    f'fontcolor="white" shape=diamond];'
                )
            lines.append("  }")

        if result.agents:
            lines.append("")
            lines.append('  subgraph cluster_agents {')
            lines.append('    label="AI Agents"; style=filled; fillcolor="#1f1a2e";')
            lines.append('    color="#a371f7"; fontcolor="#a371f7";')
            for agent in result.agents:
                node_id = f"agt_{str(agent.id).replace('-', '')[:12]}"
                color = "#ff0000" if agent.risk_score >= 7 else "#a371f7"
                label = f"{agent.agent_name or 'AI Agent'}\\nRisk: {agent.risk_score:.1f}"
                lines.append(
                    f'    {node_id} [label="{label}" style=filled fillcolor="{color}" '
                    f'fontcolor="white" shape=hexagon];'
                )
            lines.append("  }")

        if result.attack_paths:
            lines.append("")
            lines.append("  // Attack Paths")
            for path in result.attack_paths[:5]:
                assets = path.assets_involved
                if len(assets) >= 2:
                    src_id = f"svc_{str(assets[0]).replace('-', '')[:12]}"
                    dst_id = f"mcp_{str(assets[-1]).replace('-', '')[:12]}"
                    lines.append(
                        f'  {src_id} -> {dst_id} [color="#ff4444" style=dashed '
                        f'label="attack path" fontcolor="#ff4444"];'
                    )

        lines.append("}")
        return "\n".join(lines)

    def _to_mermaid(self, result: ScanResult) -> str:
        lines = [
            "```mermaid",
            "graph LR",
            "",
            "  %% AI Services",
        ]
        for svc in result.services:
            nid = f"S{str(svc.id).replace('-', '')[:8]}"
            label = f"{svc.platform or 'AI'}\\n{svc.host}:{svc.port}"
            auth = "✓" if svc.auth_required else "⚠ No Auth"
            lines.append(f'  {nid}["{label}<br/>{auth}"]')
            if not svc.auth_required:
                lines.append(f'  style {nid} fill:#ff4444,color:#fff')

        if result.mcp_servers:
            lines.append("")
            lines.append("  %% MCP Servers")
            for mcp in result.mcp_servers:
                nid = f"M{str(mcp.id).replace('-', '')[:8]}"
                label = f"{mcp.server_name or 'MCP'}\\n{len(mcp.tools)} tools"
                lines.append(f'  {nid}(("{label}"))')
                if mcp.dangerous_tools:
                    lines.append(f'  style {nid} fill:#ff6b35,color:#fff')

        if result.agents:
            lines.append("")
            lines.append("  %% AI Agents")
            for agent in result.agents:
                nid = f"A{str(agent.id).replace('-', '')[:8]}"
                label = f"{agent.agent_name or 'Agent'}"
                lines.append(f'  {nid}{{{{{label}}}}}')

        lines.append("```")
        return "\n".join(lines)

    def _dot_to_svg(self, dot_path: Path) -> Path | None:
        try:
            import subprocess
            svg_path = dot_path.with_suffix(".svg")
            result = subprocess.run(
                ["dot", "-Tsvg", str(dot_path), "-o", str(svg_path)],
                capture_output=True, timeout=30,
            )
            if result.returncode == 0:
                return svg_path
        except Exception as e:
            logger.warning(f"Graphviz not available: {e}")
        return None
