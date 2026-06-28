"""
aasm discover — Quick AI service discovery.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from aasm.cli.output import make_progress, print_banner, print_services_table
from aasm.core.config import get_config

console = Console()
app = typer.Typer(help="Quickly discover AI services on a target.")


@app.callback(invoke_without_command=True)
def discover(
    ctx: typer.Context,
    target: str = typer.Argument("127.0.0.1", help="Target host or CIDR range"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
) -> None:
    """
    Discover AI services running on a target host or network.

    Examples:

        aasm discover 192.168.1.10
        aasm discover 10.0.0.0/24 --ports 11434,3000
        aasm discover localhost --json
    """
    print_banner()
    cfg = get_config(config_path)
    port_list = [int(p) for p in ports.split(",")] if ports else None

    asyncio.run(_discover(target, port_list, cfg, json_output))


async def _discover(target: str, port_list: list[int] | None, cfg: object, json_output: bool) -> None:
    from aasm.core.config import AASMConfig
    from aasm.modules.discovery import DiscoveryEngine

    assert isinstance(cfg, AASMConfig)

    with make_progress() as progress:
        task = progress.add_task("[cyan]Discovering AI services...", total=None)
        async with DiscoveryEngine(cfg.discovery) as engine:
            services = await engine.scan(target, ports=port_list)
        progress.update(task, description=f"[green]Done — {len(services)} services found")

    if json_output:
        import json
        console.print_json(json.dumps([s.model_dump(mode="json") for s in services], default=str))
    else:
        print_services_table(services)
        if not services:
            console.print(f"\n[dim]No AI services found on {target}[/dim]")
            console.print("[dim]Try expanding port range with --ports or checking if services are running.[/dim]")
