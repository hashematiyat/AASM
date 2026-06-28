"""
AASM — AI Attack Surface Mapper
Main CLI entry point.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from aasm.cli.commands import agents, assess, audit, discover, fingerprint, graph, mcp, report, risk, scan

console = Console()

app = typer.Typer(
    name="aasm",
    help="""
[bold red]AASM[/bold red] — AI Attack Surface Mapper

Enterprise CLI for discovering, fingerprinting, and securing AI infrastructure.
Supports Local LLMs, MCP Servers, AI Agents, AI APIs, and AI Gateways.

[dim]Built for penetration testers, AI security engineers, blue teams, and red teams.[/dim]
""",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=True,
)

app.add_typer(scan.app, name="scan", help="Full network scan for AI services")
app.add_typer(discover.app, name="discover", help="Quick AI service discovery")
app.add_typer(fingerprint.app, name="fingerprint", help="Deep fingerprint a service")
app.add_typer(audit.app, name="audit", help="Audit an AI service for misconfigurations")
app.add_typer(mcp.app, name="mcp", help="Discover and audit MCP servers")
app.add_typer(agents.app, name="agents", help="Discover and analyze AI agents")
app.add_typer(assess.app, name="assess", help="AI security assessment (offensive)")
app.add_typer(graph.app, name="graph", help="Generate AI infrastructure graphs")
app.add_typer(report.app, name="report", help="Generate reports from scan results")
app.add_typer(risk.app, name="risk", help="Risk scoring and executive summaries")


@app.command("version")
def version() -> None:
    """Show AASM version."""
    from aasm import __version__
    console.print(f"[bold red]AASM[/bold red] v{__version__}")


@app.command("platforms")
def platforms() -> None:
    """List all supported AI platforms and detection capabilities."""
    from aasm.modules.discovery.platforms import ALL_DETECTORS

    t = Table(
        title="[bold]Supported AI Platforms[/bold]",
        show_header=True,
        header_style="bold blue",
        border_style="dim",
    )
    t.add_column("Platform", style="bold cyan")
    t.add_column("Type", style="dim")
    t.add_column("Default Ports", style="dim")
    t.add_column("Probe Paths", style="dim")

    for cls in ALL_DETECTORS:
        t.add_row(
            cls.platform_name,
            cls.service_type.value,
            ", ".join(str(p) for p in cls.default_ports),
            ", ".join(cls.probe_paths[:3]),
        )
    console.print(t)


@app.command("plugins")
def plugins_cmd(
    load: Optional[Path] = typer.Option(None, "--load", help="Load plugins from path"),
) -> None:
    """List and manage AASM plugins."""
    from aasm.plugins import get_registry

    registry = get_registry()
    if load:
        n = registry.load_from_path(load)
        console.print(f"[green]Loaded {n} plugins from {load}[/green]")

    plugin_list = registry.list_plugins()
    if not plugin_list:
        console.print("[dim]No plugins loaded. Use --load <path> to load plugins.[/dim]")
        return

    t = Table(show_header=True, header_style="bold")
    t.add_column("Name")
    t.add_column("Version")
    t.add_column("Type")
    t.add_column("Description")
    t.add_column("Author")

    for p in plugin_list:
        t.add_row(p["name"], p["version"], p["type"], p["description"], p["author"])
    console.print(t)


@app.command("config")
def config_cmd(
    init: bool = typer.Option(False, "--init", help="Initialize a default config file"),
    path: Path = typer.Option(Path("aasm.yaml"), "--path", help="Config file path"),
    show: bool = typer.Option(False, "--show", help="Show current effective config"),
) -> None:
    """Manage AASM configuration."""
    from aasm.core.config import AASMConfig, get_config

    if init:
        cfg = AASMConfig()
        cfg.save(path)
        console.print(f"[green]✓[/green] Config written to [cyan]{path}[/cyan]")
        return

    if show:
        import yaml
        cfg = get_config()
        console.print_json(cfg.model_dump_json(indent=2))
        return

    console.print("[dim]Use --init to create a config, --show to display current config.[/dim]")


if __name__ == "__main__":
    app()
