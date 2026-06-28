"""
aasm audit — Audit a specific AI service for security misconfigurations.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from aasm.cli.output import make_progress, print_banner, print_findings_tree, print_risk_panel
from aasm.core.models import RiskScore

console = Console()
app = typer.Typer(help="Audit AI services for security misconfigurations.")


@app.callback(invoke_without_command=True)
def audit(
    ctx: typer.Context,
    target: str = typer.Argument(..., help="Target URL (e.g. http://localhost:11434)"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """
    Audit a specific AI service for security issues.

    Combines fingerprinting + MCP analysis + security assessment.

    Examples:

        aasm audit http://localhost:11434
        aasm audit http://myserver:3000
    """
    print_banner()
    asyncio.run(_audit(target, config_path))


async def _audit(target: str, config_path: Path | None) -> None:
    from urllib.parse import urlparse
    import httpx

    from aasm.core.config import AASMConfig, get_config
    from aasm.core.models import AIService, AIServiceType
    from aasm.modules.assessment import SecurityAssessmentEngine
    from aasm.modules.fingerprint import FingerprintEngine
    from aasm.modules.mcp import MCPScanner, MCPSecurityAnalyzer
    from aasm.modules.discovery.platforms import ALL_DETECTORS
    from aasm.modules.risk import RiskEngine

    cfg = get_config(config_path)
    assert isinstance(cfg, AASMConfig)

    parsed = urlparse(target)
    host = parsed.hostname or target
    port = parsed.port or 80

    with make_progress() as progress:
        t1 = progress.add_task("[cyan]Detecting platform...", total=None)

        service = None
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
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

        progress.update(t1, description=f"[green]Platform: {service.platform or 'Unknown'}")

        t2 = progress.add_task("[cyan]Fingerprinting...", total=None)
        fp = FingerprintEngine()
        service = await fp.fingerprint(service)
        progress.update(t2, description="[green]Fingerprinting complete")

        t3 = progress.add_task("[yellow]Scanning for MCP...", total=None)
        scanner = MCPScanner()
        mcp_analyzer = MCPSecurityAnalyzer()
        mcp_servers = await scanner.scan_host(host)
        mcp_servers = [mcp_analyzer.analyze(s) for s in mcp_servers]
        progress.update(t3, description=f"[green]MCP: {len(mcp_servers)} servers")

        t4 = progress.add_task("[red]Security assessment...", total=None)
        engine = SecurityAssessmentEngine(config=cfg.assessment)
        findings = await engine.assess(service)
        for mcp in mcp_servers:
            findings.extend(mcp.findings)
        progress.update(t4, description=f"[green]Assessment: {len(findings)} findings")

    risk_engine = RiskEngine()
    enriched = risk_engine._enrich_findings(findings)
    score = RiskScore()
    if findings:
        from aasm.core.models import Severity
        weights = {Severity.CRITICAL: 4.0, Severity.HIGH: 2.5, Severity.MEDIUM: 1.0, Severity.LOW: 0.3}
        raw = min(10.0, sum(weights.get(f.severity, 0.0) for f in findings))
        score.overall = round(raw, 2)
        score.label = score.compute_label()

    print_risk_panel(score)
    print_findings_tree(findings)
