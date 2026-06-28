"""
aasm scan — Full network scan for AI services.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.rule import Rule

from aasm.cli.output import (
    make_progress,
    print_attack_paths,
    print_banner,
    print_findings_tree,
    print_mcp_table,
    print_risk_panel,
    print_scan_header,
    print_service_detail_panels,
    print_services_table,
    print_summary_stats,
)
from aasm.core.config import get_config
from aasm.core.models import ScanResult

console = Console()
app = typer.Typer(help="Scan a network or host for AI services.")


@app.callback(invoke_without_command=True)
def scan(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target IP, CIDR range, or hostname (e.g. 192.168.1.0/24)"),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Comma-separated ports (e.g. 11434,3000,8080)"),
    profile: Optional[str] = typer.Option(None, "--profile", help="Scan profile name from config"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    formats: str = typer.Option("json,html", "--formats", "-f", help="Report formats (json,html,sarif)"),
    no_fingerprint: bool = typer.Option(False, "--no-fingerprint", help="Skip deep fingerprinting"),
    no_mcp: bool = typer.Option(False, "--no-mcp", help="Skip MCP server discovery"),
    no_agents: bool = typer.Option(False, "--no-agents", help="Skip agent analysis"),
    no_risk: bool = typer.Option(False, "--no-risk", help="Skip risk calculation"),
    no_graph: bool = typer.Option(False, "--no-graph", help="Skip attack surface graph"),
    detail: bool = typer.Option(False, "--detail", "-D", help="Show per-port details (like nmap -sV -sC)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path"),
) -> None:
    """
    Run a full AI attack surface scan against a target network.

    Examples:

        aasm scan 192.168.1.0/24
        aasm scan 10.0.0.1 --ports 11434,3000,8080 --detail
        aasm scan myserver.local --profile aggressive
        aasm scan 192.168.1.0/24 --formats json,html,sarif -o ./reports
    """
    print_banner()
    cfg = get_config(config_path)

    port_list = None
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            console.print("[red]Error:[/red] Invalid port list. Use comma-separated integers.")
            raise typer.Exit(1)

    if profile:
        p = cfg.get_profile(profile)
        if p:
            port_list = port_list or p.ports
        else:
            console.print(f"[yellow]Warning:[/yellow] Profile '{profile}' not found, using defaults.")

    print_scan_header(target, port_list)
    fmt_list = [f.strip() for f in formats.split(",")]

    asyncio.run(_run_scan(
        target=target,
        port_list=port_list,
        cfg=cfg,
        output_dir=output or Path(cfg.reporting.output_dir),
        fmt_list=fmt_list,
        no_fingerprint=no_fingerprint,
        no_mcp=no_mcp,
        no_agents=no_agents,
        no_risk=no_risk,
        no_graph=no_graph,
        detail=detail,
        verbose=verbose,
    ))


async def _run_scan(
    target: str,
    port_list: list[int] | None,
    cfg: object,
    output_dir: Path,
    fmt_list: list[str],
    no_fingerprint: bool,
    no_mcp: bool,
    no_agents: bool,
    no_risk: bool,
    no_graph: bool,
    detail: bool,
    verbose: bool,
) -> None:
    from aasm.core.config import AASMConfig
    from aasm.modules.agents import AgentAnalyzer
    from aasm.modules.discovery import DiscoveryEngine
    from aasm.modules.fingerprint import FingerprintEngine
    from aasm.modules.mapper import AttackSurfaceMapper
    from aasm.modules.mcp import MCPScanner, MCPSecurityAnalyzer
    from aasm.modules.reporting import ReportingEngine
    from aasm.modules.risk import RiskEngine
    from aasm.modules.visualization import VisualizationEngine

    assert isinstance(cfg, AASMConfig)
    result = ScanResult(target=target)

    with make_progress() as progress:
        task = progress.add_task("[cyan]Discovering AI services...", total=None)

        async with DiscoveryEngine(cfg.discovery) as engine:
            progress.update(task, description="[cyan]Scanning for AI services...")
            result.services = await engine.scan(target, ports=port_list)
            result.modules_run.append("discovery")

        progress.update(task, description=f"[green]Found {len(result.services)} services")

        if not no_fingerprint and result.services:
            progress.update(task, description="[cyan]Fingerprinting services...")
            fp_engine = FingerprintEngine()
            result.services = await fp_engine.fingerprint_many(result.services)
            result.modules_run.append("fingerprint")

        if not no_mcp:
            progress.update(task, description="[cyan]Discovering MCP servers...")
            scanner = MCPScanner()
            analyzer = MCPSecurityAnalyzer()
            from aasm.modules.discovery.engine import expand_target
            hosts = expand_target(target)
            mcp_tasks = [scanner.scan_host(h) for h in hosts[:50]]
            mcp_results = await asyncio.gather(*mcp_tasks)
            raw_servers = [s for servers in mcp_results for s in servers]
            result.mcp_servers = [analyzer.analyze(s) for s in raw_servers]
            result.modules_run.append("mcp")

        if not no_agents and result.services:
            progress.update(task, description="[cyan]Analyzing AI agents...")
            agent_analyzer = AgentAnalyzer()
            result.agents = await agent_analyzer.analyze_many(result.services)
            result.modules_run.append("agents")

        if not no_graph:
            progress.update(task, description="[cyan]Building attack surface graph...")
            mapper = AttackSurfaceMapper()
            result = mapper.build(result)
            result.modules_run.append("mapper")

        if not no_risk:
            progress.update(task, description="[cyan]Calculating risk scores...")
            risk_engine = RiskEngine()
            result = risk_engine.calculate(result)
            result.modules_run.append("risk")

        progress.update(task, description="[green]Generating reports...")
        reporter = ReportingEngine(str(output_dir))
        report_paths = reporter.generate(result, fmt_list)

        viz = VisualizationEngine(str(output_dir))
        graph_paths = viz.generate(result, ["dot", "mermaid"])
        result.modules_run.append("reporting")
        progress.update(task, description="[bold green]Scan complete!", completed=True)

    console.print()
    console.print(Rule("[bold red]Scan Results[/bold red]", style="dim red"))
    print_summary_stats(result)
    console.print()
    print_risk_panel(result.risk_score)
    console.print()

    if detail:
        # Nmap-style: one rich panel per port with full details
        print_service_detail_panels(
            result.services,
            findings=result.findings,
            mcp_servers=result.mcp_servers,
        )
    else:
        # Default: compact summary table
        print_services_table(result.services)
        console.print()
        print_mcp_table(result.mcp_servers)
        console.print()
        print_findings_tree(result.findings)

    console.print()
    print_attack_paths(result)
    console.print()

    console.print(Rule("[bold]Reports[/bold]", style="dim"))
    for fmt, path in report_paths.items():
        console.print(f"  [green]✓[/green] {fmt.upper()}: [dim]{path}[/dim]")
    for fmt, path in graph_paths.items():
        console.print(f"  [green]✓[/green] Graph ({fmt}): [dim]{path}[/dim]")
