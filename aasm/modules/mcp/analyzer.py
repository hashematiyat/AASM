"""
Module 3 (cont.) — MCP Security Analyzer
Analyzes MCP server security posture: auth, permissions, trust relationships.
"""

from __future__ import annotations

from aasm.core.logger import get_logger
from aasm.core.models import AuthType, MCPServer, SecurityFinding, Severity

logger = get_logger("mcp.analyzer")


class MCPSecurityAnalyzer:
    """
    Evaluates security posture of discovered MCP servers.
    Generates findings and a risk score.
    """

    def analyze(self, server: MCPServer) -> MCPServer:
        findings: list[SecurityFinding] = []

        findings.extend(self._check_authentication(server))
        findings.extend(self._check_dangerous_tools(server))
        findings.extend(self._check_resource_exposure(server))
        findings.extend(self._check_permissions(server))
        findings.extend(self._check_excessive_capabilities(server))

        server.findings = findings
        server.risk_score = self._calculate_risk(findings)
        return server

    def _check_authentication(self, server: MCPServer) -> list[SecurityFinding]:
        if not server.auth_required or server.auth_type == AuthType.NONE:
            return [SecurityFinding(
                title="MCP Server has No Authentication",
                description=(
                    f"The MCP server '{server.server_name or server.service.host}' "
                    "is accessible without any authentication. Any user on the "
                    "network can invoke its tools and access its resources."
                ),
                severity=Severity.CRITICAL,
                category="Authentication",
                asset_id=server.id,
                asset_url=server.service.url,
                remediation="Implement authentication using OAuth 2.0 or API keys. "
                            "Restrict access to trusted clients only.",
                mitre_techniques=["T1078", "T1190"],
                owasp_categories=["LLM08:2025 - Weak Guardrails"],
            )]
        return []

    def _check_dangerous_tools(self, server: MCPServer) -> list[SecurityFinding]:
        findings = []
        for tool in server.tools:
            if tool.dangerous:
                severity = Severity.CRITICAL if any(
                    kw in tool.name.lower()
                    for kw in ["bash", "shell", "exec", "docker", "kubectl"]
                ) else Severity.HIGH

                findings.append(SecurityFinding(
                    title=f"Dangerous MCP Tool Exposed: {tool.name}",
                    description=(
                        f"The tool '{tool.name}' on MCP server "
                        f"'{server.server_name or server.service.host}' "
                        f"exposes dangerous capabilities: {', '.join(tool.risk_reasons)}. "
                        "This could allow an attacker to execute arbitrary code, "
                        "access filesystems, or escalate privileges."
                    ),
                    severity=severity,
                    category="Tool Abuse",
                    asset_id=server.id,
                    asset_url=server.service.url,
                    evidence={"tool_name": tool.name, "risk_reasons": tool.risk_reasons},
                    remediation=f"Restrict access to the '{tool.name}' tool. "
                                "Implement allowlists for callers. "
                                "Apply principle of least privilege.",
                    mitre_techniques=["T1059", "T1068"],
                    owasp_categories=["LLM06:2025 - Excessive Agency",
                                      "LLM04:2025 - Data and Model Poisoning"],
                ))
        return findings

    def _check_resource_exposure(self, server: MCPServer) -> list[SecurityFinding]:
        findings = []
        sensitive_patterns = ["secret", "key", "password", "token", "credential",
                               "private", "config", ".env", "database"]
        for resource in server.resources:
            uri_lower = resource.uri.lower()
            if any(p in uri_lower for p in sensitive_patterns):
                findings.append(SecurityFinding(
                    title=f"Sensitive Resource Exposed: {resource.uri}",
                    description=(
                        f"MCP server '{server.server_name}' exposes a resource at "
                        f"'{resource.uri}' which may contain sensitive data."
                    ),
                    severity=Severity.HIGH,
                    category="Data Exposure",
                    asset_id=server.id,
                    asset_url=server.service.url,
                    evidence={"resource_uri": resource.uri},
                    remediation="Review resource access controls. "
                                "Remove sensitive resources from MCP exposure.",
                    owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
                ))
        return findings

    def _check_permissions(self, server: MCPServer) -> list[SecurityFinding]:
        findings = []
        for perm in server.permissions:
            if perm.dangerous:
                findings.append(SecurityFinding(
                    title=f"Dangerous Permission: {perm.category}",
                    description=perm.description or f"MCP server has dangerous permission: {perm.category}",
                    severity=Severity.HIGH,
                    category="Permissions",
                    asset_id=server.id,
                    asset_url=server.service.url,
                    remediation="Remove unnecessary permissions. Apply least privilege.",
                    owasp_categories=["LLM06:2025 - Excessive Agency"],
                ))
        return findings

    def _check_excessive_capabilities(self, server: MCPServer) -> list[SecurityFinding]:
        findings = []
        capability_count = len(server.tools)
        if capability_count > 20:
            findings.append(SecurityFinding(
                title="MCP Server Has Excessive Tool Count",
                description=(
                    f"The MCP server exposes {capability_count} tools, significantly "
                    "expanding the attack surface. Each tool is a potential vector "
                    "for tool abuse or prompt injection."
                ),
                severity=Severity.MEDIUM,
                category="Attack Surface",
                asset_id=server.id,
                asset_url=server.service.url,
                remediation="Audit and remove unused tools. "
                            "Consider splitting into purpose-specific MCP servers.",
                owasp_categories=["LLM06:2025 - Excessive Agency"],
            ))
        return findings

    def _calculate_risk(self, findings: list[SecurityFinding]) -> float:
        score = 0.0
        weights = {
            Severity.CRITICAL: 4.0,
            Severity.HIGH: 2.5,
            Severity.MEDIUM: 1.0,
            Severity.LOW: 0.3,
            Severity.INFO: 0.0,
        }
        for f in findings:
            score += weights.get(f.severity, 0.0)
        return min(10.0, score)
