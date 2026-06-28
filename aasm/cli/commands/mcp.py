"""
aasm mcp — MCP server discovery and security analysis.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.rule import Rule
from rich.table import Table
from rich.tree import Tree

from aasm.cli.output import make_progress, print_banner, print_findings_tree, print_mcp_table
from aasm.core.config import get_config

console = Console()
app = typer.Typer(help="Discover and audit MCP (Model Context Protocol) servers.")


@app.callback(invoke_without_command=True)
def mcp(
    ctx: typer.Context,
    target: str = typer.Argument("127.0.0.1", help="Target host, CIDR, or URL"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p"),
    enumerate_tools: bool = typer.Option(True, "--tools/--no-tools", help="Enumerate MCP tools"),
    analyze: bool = typer.Option(True, "--analyze/--no-analyze", help="Run security analysis"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Discover MCP servers and analyze their security posture.

    Examples:

        aasm mcp 192.168.1.0/24
        aasm mcp localhost --no-analyze
        aasm mcp 10.0.0.1 --ports 3000,8080
    """
    print_banner()
    asyncio.run(_run_mcp(target, ports, enumerate_tools, analyze, config_path))


async def _run_mcp(
    target: str,
    ports: str | None,
    enumerate_tools: bool,
    analyze: bool,
    config_path: Path | None,
) -> None:
    from aasm.modules.discovery.engine import expand_target
    from aasm.modules.mcp import MCPScanner, MCPSecurityAnalyzer

    port_list = [int(p) for p in ports.split(",")] if ports else None
    scanner = MCPScanner(ports=port_list)
    analyzer = MCPSecurityAnalyzer()

    hosts = expand_target(target)
    all_servers = []

    with make_progress() as progress:
        task = progress.add_task("[yellow]Scanning for MCP servers...", total=len(hosts))
        for host in hosts:
            servers = await scanner.scan_host(host)
            all_servers.extend(servers)
            progress.advance(task)

    if analyze:
        all_servers = [analyzer.analyze(s) for s in all_servers]

    print_mcp_table(all_servers)

    for server in all_servers:
        console.print(Rule(f"[yellow]{server.server_name or server.service.host}[/yellow]", style="dim yellow"))

        if server.tools:
            tree = Tree("[bold]Tools[/bold]")
            for tool in server.tools:
                style = "bold red" if tool.dangerous else "white"
                branch = tree.add(f"[{style}]{tool.name}[/{style}]")
                if tool.description:
                    branch.add(f"[dim]{tool.description[:80]}[/dim]")
                if tool.risk_reasons:
                    branch.add(f"[red]⚠ {', '.join(tool.risk_reasons)}[/red]")
            console.print(tree)

        if server.resources:
            t = Table(title="Resources", show_header=True, header_style="bold")
            t.add_column("URI")
            t.add_column("Type")
            for res in server.resources:
                t.add_row(res.uri, res.mime_type or "—")
            console.print(t)

        if server.findings:
            print_findings_tree(server.findings)
