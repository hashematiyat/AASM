"""
Module 7 — AI Risk Engine
Calculates AI-specific security risks and exposure scores.
"""

from __future__ import annotations

from aasm.core.logger import get_logger
from aasm.core.models import (
    AIServiceType,
    AttackPath,
    RiskScore,
    ScanResult,
    SecurityFinding,
    Severity,
)

logger = get_logger("risk")

MITRE_ATLAS_MAPPING: dict[str, list[str]] = {
    "Prompt Injection": ["AML.T0051", "T1190"],
    "Jailbreak": ["AML.T0054"],
    "Model Theft": ["AML.T0038"],
    "Data Poisoning": ["AML.T0020"],
    "System Prompt Disclosure": ["AML.T0057"],
    "Tool Abuse": ["AML.T0051.002", "T1059"],
    "Excessive Agency": ["AML.T0056"],
    "Unauthenticated Access": ["T1078", "T1190"],
    "Information Disclosure": ["T1213"],
}

OWASP_LLM_TOP10_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


class RiskEngine:
    """
    Calculates risk scores for the entire AI attack surface.
    Maps findings to MITRE ATT&CK and OWASP LLM Top 10.
    """

    def calculate(self, result: ScanResult) -> ScanResult:
        result.risk_score = self._compute_overall_risk(result)
        result.findings = self._enrich_findings(result.findings)
        logger.info(
            f"Risk calculation complete — overall score: "
            f"{result.risk_score.overall:.1f} ({result.risk_score.label})"
        )
        return result

    def _compute_overall_risk(self, result: ScanResult) -> RiskScore:
        all_findings = result.findings.copy()
        for mcp in result.mcp_servers:
            all_findings.extend(mcp.findings)
        for agent in result.agents:
            all_findings.extend(agent.findings)

        severity_counts = {s: 0 for s in Severity}
        for f in all_findings:
            severity_counts[f.severity] += 1

        exposure_score = self._exposure_score(result)
        auth_score = self._auth_score(result)
        permission_score = self._permission_score(result)
        network_score = self._network_exposure_score(result)
        data_score = self._data_sensitivity_score(result)

        overall = min(10.0, (
            exposure_score * 0.25
            + auth_score * 0.25
            + permission_score * 0.20
            + network_score * 0.15
            + data_score * 0.15
        ) + severity_counts[Severity.CRITICAL] * 0.5
          + severity_counts[Severity.HIGH] * 0.2)

        overall = min(10.0, overall)
        score = RiskScore(
            overall=round(overall, 2),
            exposure=round(exposure_score, 2),
            authentication=round(auth_score, 2),
            permissions=round(permission_score, 2),
            network_exposure=round(network_score, 2),
            data_sensitivity=round(data_score, 2),
        )
        score.label = score.compute_label()
        return score

    def _exposure_score(self, result: ScanResult) -> float:
        if not result.services:
            return 0.0
        exposed = len(result.services)
        unauthenticated = sum(1 for s in result.services if not s.auth_required)
        return min(10.0, (unauthenticated / max(exposed, 1)) * 10.0)

    def _auth_score(self, result: ScanResult) -> float:
        if not result.services:
            return 0.0
        no_auth = sum(1 for s in result.services if not s.auth_required)
        mcp_no_auth = sum(1 for m in result.mcp_servers if not m.auth_required)
        return min(10.0, ((no_auth + mcp_no_auth) / max(len(result.services), 1)) * 10.0)

    def _permission_score(self, result: ScanResult) -> float:
        dangerous_tools = sum(
            len(m.dangerous_tools) for m in result.mcp_servers
        )
        critical_cap_agents = sum(
            1 for a in result.agents
            if a.risk_score >= 7.0
        )
        return min(10.0, dangerous_tools * 1.5 + critical_cap_agents * 2.0)

    def _network_exposure_score(self, result: ScanResult) -> float:
        external_services = [
            s for s in result.services
            if not s.host.startswith(("10.", "172.", "192.168.", "127."))
        ]
        return min(10.0, len(external_services) * 3.0)

    def _data_sensitivity_score(self, result: ScanResult) -> float:
        sensitive_models = sum(
            1 for s in result.services
            for m in s.models
            if any(kw in m.name.lower() for kw in ["gpt", "llama", "mistral", "claude"])
        )
        return min(10.0, sensitive_models * 2.0)

    def _enrich_findings(self, findings: list[SecurityFinding]) -> list[SecurityFinding]:
        for finding in findings:
            if not finding.mitre_techniques:
                for category, techniques in MITRE_ATLAS_MAPPING.items():
                    if category.lower() in finding.category.lower():
                        finding.mitre_techniques = techniques
                        break
        return findings

    def generate_executive_summary(self, result: ScanResult) -> str:
        score = result.risk_score
        critical = len([f for f in result.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in result.findings if f.severity == Severity.HIGH])

        summary = [
            f"## Executive Risk Summary",
            f"",
            f"**Overall Risk Score:** {score.overall:.1f}/10 ({score.label})",
            f"",
            f"### Attack Surface Overview",
            f"- AI Services Discovered: {len(result.services)}",
            f"- MCP Servers Found: {len(result.mcp_servers)}",
            f"- AI Agents Identified: {len(result.agents)}",
            f"- Attack Paths Mapped: {len(result.attack_paths)}",
            f"",
            f"### Finding Summary",
            f"- Critical: {critical}",
            f"- High: {high}",
            f"- Total: {len(result.findings)}",
            f"",
            f"### Risk Scores by Category",
            f"- Exposure: {score.exposure:.1f}/10",
            f"- Authentication: {score.authentication:.1f}/10",
            f"- Permissions: {score.permissions:.1f}/10",
            f"- Network Exposure: {score.network_exposure:.1f}/10",
        ]

        if result.attack_paths:
            summary.append(f"")
            summary.append(f"### Critical Attack Paths")
            for path in result.attack_paths[:3]:
                summary.append(f"- **{path.name}**: {path.description[:100]}...")

        return "\n".join(summary)
