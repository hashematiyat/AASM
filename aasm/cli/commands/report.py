"""
aasm report — Generate reports from a previous scan JSON.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from aasm.cli.output import print_banner

console = Console()
app = typer.Typer(help="Generate reports from a previous scan JSON result.")


@app.callback(invoke_without_command=True)
def report(
    ctx: typer.Context,
    input_file: Path = typer.Argument(..., help="Path to AASM JSON scan result"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
    formats: str = typer.Option("html,sarif", "--formats", "-f"),
) -> None:
    """
    Generate HTML/SARIF/PDF reports from a saved JSON scan result.

    Examples:

        aasm report scan_result.json
        aasm report scan_result.json --formats html,sarif -o ./reports
    """
    print_banner()

    if not input_file.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(1)

    from aasm.core.models import ScanResult
    from aasm.modules.reporting import ReportingEngine

    with open(input_file) as f:
        data = json.load(f)

    result = ScanResult.model_validate(data)
    out_dir = output or Path("./aasm_reports")
    fmt_list = [f.strip() for f in formats.split(",")]

    reporter = ReportingEngine(str(out_dir))
    paths = reporter.generate(result, fmt_list)

    console.print(f"[green]Reports generated:[/green]")
    for fmt, path in paths.items():
        console.print(f"  [green]✓[/green] {fmt.upper()}: [dim]{path}[/dim]")
