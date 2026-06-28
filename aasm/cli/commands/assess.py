"""
aasm assess — AI security assessment (offensive testing).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.rule import Rule

from aasm.cli.output import make_progress, print_banner, print_findings_tree
from aasm.core.config import get_config

console = Console()
app = typer.Typer(help="Perform AI security assessments (prompt injection, jailbreak, etc.)")


@app.callback(invoke_without_command=True)
def assess(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target URL (e.g. http://localhost:11434)"),
    prompt_injection: bool = typer.Option(True, "--prompt-injection/--no-prompt-injection"),
    prompt_leakage: bool = typer.Option(True, "--prompt-leakage/--no-prompt-leakage"),
    jailbreak: bool = typer.Option(False, "--jailbreak/--no-jailbreak", help="Run jailbreak tests (aggressive)"),
    auth_bypass: bool = typer.Option(True, "--auth-bypass/--no-auth-bypass"),
    max_payloads: int = typer.Option(10, "--max-payloads", help="Max payloads per test category"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Perform AI-specific security assessments against a target AI service.

    Examples:

        aasm assess http://localhost:11434
        aasm assess http://myserver:3000 --jailbreak
        aasm assess http://litellm:4000 --no-prompt-injection
    """
    print_banner()
    console.print(f"[bold red]⚠ WARNING:[/bold red] Only assess systems you own or have permission to test.")
    console.print()
    asyncio.run(_run_assess(target, prompt_injection, prompt_leakage, jailbreak, auth_bypass, max_payloads, config_path))


async def _run_assess(
    target: str,
    prompt_injection: bool,
    prompt_leakage: bool,
    jailbreak: bool,
    auth_bypass: bool,
    max_payloads: int,
    config_path: Path | None,
) -> None:
    from aasm.core.config import AssessmentConfig, AASMConfig, get_config
    from aasm.core.models import AIService, AIServiceType
    from aasm.modules.assessment import SecurityAssessmentEngine

    cfg = get_config(config_path)
    assert isinstance(cfg, AASMConfig)

    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    service = AIService(
        host=host,
        port=port,
        url=target,
        service_type=AIServiceType.AI_API,
        tls=parsed.scheme == "https",
    )

    assessment_cfg = AssessmentConfig(
        prompt_injection=prompt_injection,
        prompt_leakage=prompt_leakage,
        jailbreak=jailbreak,
        max_payloads=max_payloads,
    )

    engine = SecurityAssessmentEngine(config=assessment_cfg)

    with make_progress() as progress:
        task = progress.add_task("[red]Running security assessment...", total=None)
        findings = await engine.assess(service)
        progress.update(task, description=f"[green]Assessment complete — {len(findings)} findings")

    console.print(Rule("[bold red]Assessment Results[/bold red]", style="dim red"))
    print_findings_tree(findings)

    if not findings:
        console.print("[green]✓ No vulnerabilities detected in this assessment run.[/green]")
        console.print("[dim]Note: A clean result does not guarantee security. Expand tests for comprehensive coverage.[/dim]")
