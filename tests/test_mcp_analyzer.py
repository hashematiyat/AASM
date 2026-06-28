"""Tests for the MCP security analyzer."""

import pytest
from aasm.core.models import AIService, AIServiceType, AuthType, MCPServer, MCPTool, Severity
from aasm.modules.mcp.analyzer import MCPSecurityAnalyzer


def _make_mcp_server(auth_required: bool = False, tools: list[MCPTool] | None = None) -> MCPServer:
    svc = AIService(
        host="test", port=3000, url="http://test:3000",
        service_type=AIServiceType.MCP_SERVER,
    )
    return MCPServer(
        service=svc,
        server_name="Test MCP",
        auth_required=auth_required,
        auth_type=AuthType.NONE if not auth_required else AuthType.BEARER_TOKEN,
        tools=tools or [],
    )


def test_no_auth_finding():
    analyzer = MCPSecurityAnalyzer()
    server = _make_mcp_server(auth_required=False)
    result = analyzer.analyze(server)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    auth_findings = [f for f in result.findings if "Authentication" in f.title]
    assert len(auth_findings) > 0


def test_auth_present_no_auth_finding():
    analyzer = MCPSecurityAnalyzer()
    server = _make_mcp_server(auth_required=True)
    result = analyzer.analyze(server)
    auth_findings = [f for f in result.findings if "No Authentication" in f.title]
    assert len(auth_findings) == 0


def test_dangerous_tool_finding():
    tools = [
        MCPTool(
            name="bash_execute",
            description="Run bash commands",
            dangerous=True,
            risk_reasons=["Shell command execution"],
        )
    ]
    analyzer = MCPSecurityAnalyzer()
    server = _make_mcp_server(auth_required=True, tools=tools)
    result = analyzer.analyze(server)
    tool_findings = [f for f in result.findings if "bash_execute" in f.title]
    assert len(tool_findings) > 0
    assert tool_findings[0].severity in (Severity.CRITICAL, Severity.HIGH)


def test_risk_score_increases_with_findings():
    tools = [
        MCPTool(name="bash", dangerous=True, risk_reasons=["Shell"]),
        MCPTool(name="docker", dangerous=True, risk_reasons=["Docker"]),
    ]
    analyzer = MCPSecurityAnalyzer()
    server = _make_mcp_server(auth_required=False, tools=tools)
    result = analyzer.analyze(server)
    assert result.risk_score > 0.0


def test_scanner_dangerous_tool_detection():
    from aasm.modules.mcp.scanner import MCPScanner
    scanner = MCPScanner()
    dangerous, reasons = scanner._check_dangerous_tool("bash_execute")
    assert dangerous
    assert len(reasons) > 0

    safe, reasons = scanner._check_dangerous_tool("list_files_readonly")
    assert not safe
