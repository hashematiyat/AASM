"""
aasm graph — Visualize AI attack surface.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from aasm.cli.output import print_banner

console = Console()
app = typer.Typer(help="Generate AI infrastructure graphs.")


@app.callback(invoke_without_command=True)
def graph(
    ctx: typer.Context,
    input_file: Path = typer.Argument(..., help="Path to AASM JSON scan result"),
    output: Path = typer.Option(Path("./aasm_reports"), "--output", "-o"),
    formats: str = typer.Option("dot,mermaid,svg", "--formats", "-f"),
) -> None:
    """
    Generate attack surface graphs from a scan result.

    Examples:

        aasm graph scan_result.json
        aasm graph scan_result.json --formats dot,svg
    """
    print_banner()

    import json
    from aasm.core.models import ScanResult
    from aasm.modules.visualization import VisualizationEngine

    with open(input_file) as f:
        data = json.load(f)

    result = ScanResult.model_validate(data)
    fmt_list = [f.strip() for f in formats.split(",")]
    viz = VisualizationEngine(str(output))
    paths = viz.generate(result, fmt_list)

    console.print("[green]Graphs generated:[/green]")
    for fmt, path in paths.items():
        console.print(f"  [green]✓[/green] {fmt}: [dim]{path}[/dim]")
