"""
aasm agents — AI agent discovery and analysis.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

from aasm.cli.output import make_progress, print_banner, print_findings_tree
from aasm.core.config import get_config

console = Console()
app = typer.Typer(help="Discover and analyze autonomous AI agents.")


@app.callback(invoke_without_command=True)
def agents(
    ctx: typer.Context,
    target: str = typer.Argument("127.0.0.1", help="Target host or CIDR"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Discover AI agent frameworks and analyze their security posture.

    Examples:

        aasm agents 192.168.1.0/24
        aasm agents localhost --ports 3000,3001
    """
    print_banner()
    asyncio.run(_run_agents(target, ports, config_path))


async def _run_agents(target: str, ports: str | None, config_path: Path | None) -> None:
    from aasm.core.config import AASMConfig, get_config
    from aasm.modules.agents import AgentAnalyzer
    from aasm.modules.discovery import DiscoveryEngine

    cfg = get_config(config_path)
    assert isinstance(cfg, AASMConfig)
    port_list = [int(p) for p in ports.split(",")] if ports else None

    with make_progress() as progress:
        t1 = progress.add_task("[cyan]Discovering services...", total=None)
        async with DiscoveryEngine(cfg.discovery) as engine:
            services = await engine.scan(target, ports=port_list)
        progress.update(t1, description=f"[green]Found {len(services)} services")

        t2 = progress.add_task("[magenta]Analyzing agents...", total=len(services))
        analyzer = AgentAnalyzer()
        agent_list = []
        for svc in services:
            agent = await analyzer.analyze_service(svc)
            if agent:
                agent_list.append(agent)
            progress.advance(t2)

    if not agent_list:
        console.print("[dim]No AI agents detected.[/dim]")
        return

    t = Table(title=f"AI Agents ({len(agent_list)})", show_header=True, header_style="bold magenta")
    t.add_column("Agent", style="bold")
    t.add_column("Framework")
    t.add_column("Capabilities", style="dim")
    t.add_column("Integrations", justify="right")
    t.add_column("Risk", justify="right")

    for agent in agent_list:
        risk_style = "bold red" if agent.risk_score >= 7 else "yellow" if agent.risk_score >= 4 else "green"
        caps = ", ".join(c.value for c in agent.capabilities[:3])
        t.add_row(
            agent.agent_name or "Unknown",
            agent.framework or "—",
            caps or "—",
            str(len(agent.external_integrations)),
            f"[{risk_style}]{agent.risk_score:.1f}[/{risk_style}]",
        )
    console.print(t)

    for agent in agent_list:
        if agent.findings:
            console.print(Rule(f"[magenta]{agent.agent_name}[/magenta]", style="dim"))
            print_findings_tree(agent.findings)
