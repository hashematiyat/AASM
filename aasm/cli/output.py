"""
Rich terminal output helpers for AASM CLI.
Banners, tables, finding trees, and progress displays.
"""

from __future__ import annotations

from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from aasm.core.models import (
    AIService,
    MCPServer,
    RiskScore,
    ScanResult,
    SecurityFinding,
    Severity,
)

console = Console()

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold red1",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold green",
    Severity.INFO: "bold cyan",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "🔵",
}

BANNER = r"""
[bold red]    ___   ___   ____  __  ___
   / _ | / _ | / __/ /  |/  /
  / __ |/ __ |_\ \ / /|_/ /
 /_/ |_/_/ |_/___//_/  /_/[/bold red]
[dim]  AI Attack Surface Mapper v0.1.0[/dim]
[dim]  Enterprise AI Security Platform[/dim]
"""


def print_banner() -> None:
    console.print(BANNER)
    console.print(Rule(style="dim red"))


def print_scan_header(target: str, ports: list[int] | None = None) -> None:
    info = f"[bold]Target:[/bold] [cyan]{target}[/cyan]"
    if ports:
        info += f"  [bold]Ports:[/bold] [dim]{len(ports)} ports[/dim]"
    console.print(Panel(info, title="[bold red]Scan Configuration[/bold red]", border_style="dim red"))


def make_progress() -> Progress:
    return Progress(
        SpinnerColumn(spinner_name="dots", style="red"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30, style="red", complete_style="bold red"),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def print_services_table(services: list[AIService]) -> None:
    if not services:
        console.print("[dim]  No AI services discovered.[/dim]")
        return

    t = Table(
        title=f"[bold]AI Services Discovered ({len(services)})[/bold]",
        show_header=True,
        header_style="bold blue",
        border_style="dim",
        highlight=True,
    )
    t.add_column("Platform", style="bold cyan", no_wrap=True)
    t.add_column("Host", style="white")
    t.add_column("Port", justify="right", style="dim")
    t.add_column("Type", style="dim")
    t.add_column("Auth", justify="center")
    t.add_column("Models", justify="right")
    t.add_column("Endpoints", justify="right")
    t.add_column("RT (ms)", justify="right", style="dim")

    for svc in services:
        auth_text = Text("✓ Auth", style="green") if svc.auth_required else Text("✗ None", style="bold red")
        rt = f"{svc.response_time_ms:.0f}" if svc.response_time_ms else "—"
        t.add_row(
            svc.platform or "Unknown",
            svc.host,
            str(svc.port),
            svc.service_type.value,
            auth_text,
            str(len(svc.models)),
            str(len(svc.endpoints)),
            rt,
        )
    console.print(t)


def print_mcp_table(servers: list[MCPServer]) -> None:
    if not servers:
        return

    t = Table(
        title=f"[bold]MCP Servers ({len(servers)})[/bold]",
        show_header=True,
        header_style="bold yellow",
        border_style="dim",
    )
    t.add_column("Server", style="bold yellow")
    t.add_column("Host", style="white")
    t.add_column("Auth", justify="center")
    t.add_column("Tools", justify="right")
    t.add_column("Resources", justify="right")
    t.add_column("Dangerous", justify="right", style="bold red")
    t.add_column("Risk", justify="right")

    for mcp in servers:
        auth_text = Text("✓", style="green") if mcp.auth_required else Text("✗", style="bold red")
        risk_style = "bold red" if mcp.risk_score >= 7 else "yellow" if mcp.risk_score >= 4 else "green"
        t.add_row(
            mcp.server_name or "MCP Server",
            mcp.service.host,
            auth_text,
            str(len(mcp.tools)),
            str(len(mcp.resources)),
            str(len(mcp.dangerous_tools)),
            Text(f"{mcp.risk_score:.1f}", style=risk_style),
        )
    console.print(t)


def print_findings_tree(findings: list[SecurityFinding], max_show: int = 20) -> None:
    if not findings:
        console.print("[dim]  No findings.[/dim]")
        return

    tree = Tree(f"[bold]Security Findings ({len(findings)})[/bold]")

    by_severity: dict[Severity, list[SecurityFinding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        style = SEVERITY_STYLES[sev]
        icon = SEVERITY_ICONS[sev]
        branch = tree.add(f"{icon} [{style}]{sev.value}[/{style}] ({len(group)})")
        for f in group[:max_show]:
            sub = branch.add(f"[white]{f.title}[/white]")
            sub.add(f"[dim]{f.description[:100]}...[/dim]" if len(f.description) > 100 else f"[dim]{f.description}[/dim]")
            if f.remediation:
                sub.add(f"[dim green]Fix: {f.remediation[:80]}[/dim green]")
            if f.owasp_categories:
                sub.add(f"[dim cyan]OWASP: {', '.join(f.owasp_categories[:2])}[/dim cyan]")

    console.print(tree)


def print_risk_panel(score: RiskScore) -> None:
    style_map = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "bold cyan",
        "UNKNOWN": "dim",
    }
    style = style_map.get(score.label, "dim")

    content = f"""
  [bold]Overall Risk Score:[/bold] [{style}]{score.overall:.1f}/10 — {score.label}[/{style}]

  [dim]Exposure:        {_bar(score.exposure)}  {score.exposure:.1f}[/dim]
  [dim]Authentication:  {_bar(score.authentication)}  {score.authentication:.1f}[/dim]
  [dim]Permissions:     {_bar(score.permissions)}  {score.permissions:.1f}[/dim]
  [dim]Network:         {_bar(score.network_exposure)}  {score.network_exposure:.1f}[/dim]
  [dim]Data Sensitivity:{_bar(score.data_sensitivity)}  {score.data_sensitivity:.1f}[/dim]
"""
    console.print(Panel(content, title="[bold red]Risk Score[/bold red]", border_style="red"))


def _bar(value: float, width: int = 20) -> str:
    filled = int((value / 10.0) * width)
    color = "red" if value >= 7 else "yellow" if value >= 4 else "green"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * (width - filled)}[/dim]"


def print_attack_paths(result: ScanResult) -> None:
    if not result.attack_paths:
        return
    console.print(Rule("[bold red]Attack Paths[/bold red]", style="dim red"))
    for i, path in enumerate(result.attack_paths, 1):
        style = SEVERITY_STYLES.get(path.severity, "dim")
        panel_content = f"[dim]{path.description}[/dim]\n\n"
        for j, step in enumerate(path.steps, 1):
            panel_content += f"  [bold]{j}.[/bold] {step}\n"
        if path.impact:
            panel_content += f"\n  [bold red]Impact:[/bold red] {path.impact}"
        console.print(Panel(
            panel_content,
            title=f"[{style}]{i}. {path.name}[/{style}]",
            border_style="dim red",
        ))


def print_summary_stats(result: ScanResult) -> None:
    items = [
        Panel(f"[bold cyan]{len(result.services)}[/bold cyan]\n[dim]AI Services[/dim]", border_style="dim blue"),
        Panel(f"[bold yellow]{len(result.mcp_servers)}[/bold yellow]\n[dim]MCP Servers[/dim]", border_style="dim yellow"),
        Panel(f"[bold magenta]{len(result.agents)}[/bold magenta]\n[dim]AI Agents[/dim]", border_style="dim magenta"),
        Panel(f"[bold red]{len(result.critical_findings)}[/bold red]\n[dim]Critical[/dim]", border_style="dim red"),
        Panel(f"[bold]{len(result.findings)}[/bold]\n[dim]Findings[/dim]", border_style="dim"),
        Panel(f"[bold orange3]{len(result.attack_paths)}[/bold orange3]\n[dim]Attack Paths[/dim]", border_style="dim red"),
    ]
    console.print(Columns(items, equal=True, expand=True))


# ─── Nmap-style per-port detail panels ────────────────────────────────────────

DANGEROUS_ENDPOINT_LABELS: dict[str, str] = {
    "/api/admin": "Admin interface exposed",
    "/api/admin/config": "Admin config endpoint exposed",
    "/management/models": "Model management API exposed",
    "/management/team": "Team management exposed",
    "/v1/key/generate": "API key generation endpoint",
    "/api/v1/apikey": "API key management endpoint",
    "/api/v1/credentials": "Credentials endpoint — leaks secrets",
    "/metrics": "Prometheus metrics exposed",
    "/api/users": "User listing endpoint",
    "/api/v1/chatflows": "Chatflow listing exposed",
}

AUTH_LABELS: dict[str, tuple[str, str, str]] = {
    "none":         ("✗", "bold red",   "NONE  — No authentication required"),
    "api_key":      ("✓", "bold green", "API Key"),
    "bearer_token": ("✓", "bold green", "Bearer Token"),
    "basic":        ("✓", "bold green", "Basic Auth"),
    "oauth2":       ("✓", "bold green", "OAuth 2.0"),
    "mtls":         ("✓", "bold green", "mTLS"),
    "unknown":      ("?", "dim",        "Unknown"),
}

SERVICE_TYPE_LABELS: dict[str, str] = {
    "local_llm":          "Local LLM",
    "ai_api":             "AI API",
    "ai_gateway":         "AI Gateway",
    "ai_agent":           "AI Agent",
    "mcp_server":         "MCP Server",
    "ai_web_ui":          "AI Web UI",
    "vector_db":          "Vector DB",
    "embedding_service":  "Embedding Service",
    "unknown":            "Unknown",
}


def _sev_icon(sev: "Severity") -> str:
    return SEVERITY_ICONS.get(sev, "•")


def _sev_style(sev: "Severity") -> str:
    return SEVERITY_STYLES.get(sev, "white")


def print_service_detail_panels(
    services: list[AIService],
    findings: list["SecurityFinding"] | None = None,
    mcp_servers: list[MCPServer] | None = None,
) -> None:
    """
    Print one rich panel per discovered service — like Nmap -sV -sC output.
    Shows port, platform, version, auth, models, endpoints, and findings.
    """
    if not services:
        console.print("[dim]  No AI services discovered.[/dim]")
        return

    findings = findings or []
    mcp_map: dict[int, MCPServer] = {}
    for mcp in (mcp_servers or []):
        mcp_map[mcp.service.port] = mcp

    # index findings by asset_id for quick lookup
    from collections import defaultdict
    findings_by_asset: dict[str, list["SecurityFinding"]] = defaultdict(list)
    for f in findings:
        if f.asset_id:
            findings_by_asset[str(f.asset_id)].append(f)

    console.print(Rule("[bold red]Port Details[/bold red]", style="dim red"))

    for svc in services:
        _print_single_service_panel(svc, findings_by_asset, mcp_map.get(svc.port))

    # print any MCP servers that were discovered on ports NOT in services list
    printed_mcp_ports = {svc.port for svc in services}
    for mcp in (mcp_servers or []):
        if mcp.service.port not in printed_mcp_ports:
            _print_single_service_panel(mcp.service, findings_by_asset, mcp)


def _print_single_service_panel(
    svc: AIService,
    findings_by_asset: dict[str, list["SecurityFinding"]],
    mcp: MCPServer | None = None,
) -> None:
    from rich.text import Text

    # ── header line ──
    protocol = "https" if svc.tls else "http"
    stype = SERVICE_TYPE_LABELS.get(svc.service_type.value, svc.service_type.value)
    rt_str = f"  [dim]{svc.response_time_ms:.0f}ms[/dim]" if svc.response_time_ms else ""

    header = (
        f"[bold white]PORT {svc.port}/tcp[/bold white]  "
        f"[bold green]OPEN[/bold green]  "
        f"[bold cyan]{svc.platform or svc.service_type.value}[/bold cyan]  "
        f"[dim]{svc.version or ''}[/dim]{rt_str}"
    )
    sub = f"[dim]{protocol}://{svc.host}:{svc.port}  •  {stype}[/dim]"

    # ── auth line ──
    auth_key = svc.auth_type.value if svc.auth_type else "unknown"
    icon, style, label = AUTH_LABELS.get(auth_key, ("?", "dim", "Unknown"))
    auth_line = f"  [bold]Auth:[/bold]    [{style}]{icon} {label}[/{style}]"

    # ── TLS line ──
    if svc.tls:
        tls_line = "  [bold]TLS:[/bold]     [green]✓ HTTPS[/green]"
    else:
        tls_line = "  [bold]TLS:[/bold]     [red]✗ Plain HTTP — traffic is unencrypted[/red]"

    # ── version / metadata ──
    version_line = ""
    if svc.version:
        version_line = f"  [bold]Version:[/bold] [cyan]{svc.version}[/cyan]"

    openapi = svc.metadata.get("openapi_title", "")
    framework_line = ""
    if openapi:
        framework_line = f"  [bold]Framework:[/bold] [dim]{openapi} (OpenAPI documented)[/dim]"

    # ── models block ──
    models_block = ""
    if svc.models:
        model_names = [m.name for m in svc.models]
        shown = model_names[:6]
        extra = len(model_names) - len(shown)
        models_str = "  [dim]•[/dim]  ".join(f"[cyan]{n}[/cyan]" for n in shown)
        if extra > 0:
            models_str += f"  [dim]+{extra} more[/dim]"
        models_block = f"\n  [bold]Models ({len(svc.models)}):[/bold]\n    {models_str}"

    # ── endpoints block ──
    endpoints_block = ""
    dangerous_endpoints = svc.metadata.get("dangerous_endpoints", [])
    dangerous_set = set(dangerous_endpoints)
    if svc.endpoints:
        ep_lines: list[str] = []
        for ep in svc.endpoints[:12]:
            if ep in dangerous_set:
                label_d = DANGEROUS_ENDPOINT_LABELS.get(ep, "Sensitive endpoint")
                ep_lines.append(f"    [bold red]⚠ {ep:<30}[/bold red] [red]{label_d}[/red]")
            else:
                ep_lines.append(f"    [dim]{ep}[/dim]")
        extra_ep = len(svc.endpoints) - len(ep_lines)
        ep_body = "\n".join(ep_lines)
        if extra_ep > 0:
            ep_body += f"\n    [dim]+{extra_ep} more endpoints[/dim]"
        endpoints_block = f"\n  [bold]Endpoints ({len(svc.endpoints)}):[/bold]\n{ep_body}"

    # ── MCP tools block ──
    mcp_block = ""
    if mcp and mcp.tools:
        dangerous_tools = [t for t in mcp.tools if t.dangerous]
        safe_tools = [t for t in mcp.tools if not t.dangerous]

        tool_lines: list[str] = []
        for t in dangerous_tools[:8]:
            tool_lines.append(f"    [bold red]⚠ {t.name:<28}[/bold red] [red]{(t.description or '')[:50]}[/red]")
        for t in safe_tools[:4]:
            tool_lines.append(f"    [dim]{t.name:<28} {(t.description or '')[:50]}[/dim]")

        extra_t = len(mcp.tools) - len(tool_lines)
        mcp_body = "\n".join(tool_lines)
        if extra_t > 0:
            mcp_body += f"\n    [dim]+{extra_t} more tools[/dim]"
        mcp_block = (
            f"\n  [bold]MCP Tools ({len(mcp.tools)}) — "
            f"[red]{len(dangerous_tools)} DANGEROUS[/red]:[/bold]\n{mcp_body}"
        )

    # ── tags ──
    tags_line = ""
    if svc.tags:
        tags_str = "  [dim]•[/dim]  ".join(f"[dim]{t}[/dim]" for t in svc.tags)
        tags_line = f"\n  [bold]Tags:[/bold]    {tags_str}"

    # ── findings block ──
    findings_block = ""
    svc_findings = findings_by_asset.get(str(svc.id), [])
    if mcp:
        svc_findings = svc_findings + mcp.findings
    if svc_findings:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        svc_findings_sorted = sorted(
            svc_findings, key=lambda f: sev_order.get(f.severity.value, 9)
        )
        f_lines: list[str] = []
        for f in svc_findings_sorted[:6]:
            icon = _sev_icon(f.severity)
            style = _sev_style(f.severity)
            f_lines.append(
                f"    {icon} [{style}]{f.severity.value:<8}[/{style}]  [white]{f.title}[/white]"
            )
            if f.owasp_categories:
                f_lines.append(f"            [dim cyan]{f.owasp_categories[0]}[/dim cyan]")
            if f.remediation:
                f_lines.append(f"            [dim green]Fix: {f.remediation[:70]}[/dim green]")
        extra_f = len(svc_findings) - len(f_lines)
        findings_body = "\n".join(f_lines)
        findings_block = f"\n  [bold]Security Findings ({len(svc_findings)}):[/bold]\n{findings_body}"

    # ── assemble body ──
    body = sub + "\n"
    if version_line:
        body += "\n" + version_line
    if framework_line:
        body += "\n" + framework_line
    body += "\n" + auth_line
    body += "\n" + tls_line
    if models_block:
        body += "\n" + models_block
    if endpoints_block:
        body += "\n" + endpoints_block
    if mcp_block:
        body += "\n" + mcp_block
    if tags_line:
        body += "\n" + tags_line
    if findings_block:
        body += "\n" + findings_block

    # ── border color by severity ──
    has_critical = any(
        f.severity.value == "CRITICAL"
        for f in (findings_by_asset.get(str(svc.id), []) + (mcp.findings if mcp else []))
    )
    has_high = any(
        f.severity.value == "HIGH"
        for f in (findings_by_asset.get(str(svc.id), []) + (mcp.findings if mcp else []))
    )
    border = "red" if has_critical else "yellow" if has_high else "dim"

    console.print(Panel(body, title=header, border_style=border, padding=(0, 1)))
    console.print()
