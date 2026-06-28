"""
aasm fingerprint — Deep fingerprint a specific AI service.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from aasm.cli.output import print_banner
from aasm.core.models import AIService, AIServiceType

console = Console()
app = typer.Typer(help="Deep fingerprint a specific AI service.")


@app.callback(invoke_without_command=True)
def fingerprint(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target URL (e.g. http://localhost:11434)"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Perform deep fingerprinting of a specific AI service URL.

    Examples:

        aasm fingerprint http://localhost:11434
        aasm fingerprint http://myserver:3000
    """
    print_banner()
    asyncio.run(_fingerprint(target))


async def _fingerprint(target: str) -> None:
    from urllib.parse import urlparse
    from aasm.modules.fingerprint import FingerprintEngine
    from aasm.modules.discovery.platforms import ALL_DETECTORS
    import httpx

    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or 80

    console.print(f"[cyan]Fingerprinting:[/cyan] {target}")

    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        service = None
        for DetectorClass in ALL_DETECTORS:
            detector = DetectorClass(client)
            try:
                svc = await detector.detect(host, port)
                if svc:
                    service = svc
                    break
            except Exception:
                continue

    if not service:
        service = AIService(
            host=host, port=port, url=target, service_type=AIServiceType.UNKNOWN
        )

    engine = FingerprintEngine()
    service = await engine.fingerprint(service)

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column("Field", style="bold dim", width=20)
    t.add_column("Value", style="white")

    t.add_row("Platform", service.platform or "Unknown")
    t.add_row("Service Type", service.service_type.value)
    t.add_row("Version", service.version or "Unknown")
    t.add_row("URL", service.url)
    t.add_row("TLS", "Yes" if service.tls else "No")
    t.add_row("Auth Required", "Yes" if service.auth_required else "No")
    t.add_row("Auth Type", service.auth_type.value)
    t.add_row("Models Found", str(len(service.models)))
    t.add_row("Endpoints Found", str(len(service.endpoints)))
    t.add_row("Tags", ", ".join(service.tags) or "—")

    console.print(t)

    if service.models:
        console.print("\n[bold]Models:[/bold]")
        for m in service.models[:10]:
            console.print(f"  [cyan]{m.name}[/cyan]" + (f"  [dim]{m.size}[/dim]" if m.size else ""))

    if service.endpoints:
        console.print("\n[bold]Endpoints:[/bold]")
        for ep in service.endpoints:
            console.print(f"  [dim]{ep}[/dim]")

    if service.metadata.get("dangerous_endpoints"):
        console.print("\n[bold red]Dangerous Endpoints:[/bold red]")
        for ep in service.metadata["dangerous_endpoints"]:
            console.print(f"  [red]⚠ {ep}[/red]")
