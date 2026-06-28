"""
aasm risk — Risk scoring and executive summary.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console

from aasm.cli.output import print_banner, print_risk_panel

console = Console()
app = typer.Typer(help="Calculate AI risk scores and generate executive summaries.")


@app.callback(invoke_without_command=True)
def risk(
    ctx: typer.Context,
    input_file: Path = typer.Argument(..., help="Path to AASM JSON scan result"),
    executive: bool = typer.Option(True, "--executive/--no-executive", help="Print executive summary"),
) -> None:
    """
    Calculate risk scores and display an executive summary.

    Examples:

        aasm risk scan_result.json
        aasm risk scan_result.json --no-executive
    """
    print_banner()

    from aasm.core.models import ScanResult
    from aasm.modules.risk import RiskEngine

    with open(input_file) as f:
        data = json.load(f)

    result = ScanResult.model_validate(data)
    engine = RiskEngine()
    result = engine.calculate(result)

    print_risk_panel(result.risk_score)

    if executive:
        summary = engine.generate_executive_summary(result)
        console.print()
        console.print(summary)
