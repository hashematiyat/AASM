"""
Module 4 — AI Agent Analyzer
Discovers autonomous AI agents and evaluates their security posture.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from aasm.core.logger import get_logger
from aasm.core.models import (
    AIAgent,
    AIService,
    AgentCapability,
    SecurityFinding,
    Severity,
)

logger = get_logger("agents")

AGENT_FRAMEWORK_SIGNATURES: dict[str, dict[str, Any]] = {
    "Flowise": {
        "endpoints": ["/api/v1/chatflows", "/api/v1/tools"],
        "capabilities": [AgentCapability.API_CALLS, AgentCapability.WEB_BROWSING],
    },
    "Langflow": {
        "endpoints": ["/api/v1/flows", "/api/v1/components"],
        "capabilities": [AgentCapability.API_CALLS, AgentCapability.CODE_EXECUTION],
    },
    "AutoGen": {
        "endpoints": ["/agents", "/conversations"],
        "capabilities": [AgentCapability.CODE_EXECUTION, AgentCapability.MULTI_AGENT],
    },
    "CrewAI": {
        "endpoints": ["/api/crews", "/api/agents"],
        "capabilities": [AgentCapability.MULTI_AGENT, AgentCapability.API_CALLS],
    },
    "AnythingLLM": {
        "endpoints": ["/api/workspace", "/api/system/env-dump"],
        "capabilities": [AgentCapability.FILE_SYSTEM, AgentCapability.WEB_BROWSING],
    },
}

DANGEROUS_CAPABILITY_FINDINGS = {
    AgentCapability.CODE_EXECUTION: (
        Severity.CRITICAL, "Agent Can Execute Arbitrary Code",
        "The agent has code execution capabilities, which could allow "
        "prompt injection attacks to execute malicious code.",
    ),
    AgentCapability.SHELL: (
        Severity.CRITICAL, "Agent Has Shell Access",
        "The agent can execute shell commands, providing a path to "
        "full system compromise via prompt injection.",
    ),
    AgentCapability.DOCKER: (
        Severity.CRITICAL, "Agent Has Docker Access",
        "The agent can interact with Docker, enabling container escape and "
        "host system compromise.",
    ),
    AgentCapability.FILE_SYSTEM: (
        Severity.HIGH, "Agent Has Filesystem Access",
        "The agent can read and write files, enabling data exfiltration "
        "or persistent malware installation.",
    ),
    AgentCapability.DATABASE: (
        Severity.HIGH, "Agent Has Database Access",
        "The agent can query databases, enabling SQL injection or data exfiltration "
        "through prompt manipulation.",
    ),
    AgentCapability.KUBERNETES: (
        Severity.CRITICAL, "Agent Has Kubernetes Access",
        "The agent has Kubernetes API access, enabling cluster-wide privilege escalation.",
    ),
}


class AgentAnalyzer:
    """Discovers and analyzes autonomous AI agents."""

    def __init__(self, timeout: float = 10.0, verify_ssl: bool = False) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def analyze_service(self, service: AIService) -> AIAgent | None:
        """Attempt to analyze a service as an AI agent framework."""
        async with httpx.AsyncClient(
            verify=self.verify_ssl, timeout=self.timeout
        ) as client:
            return await self._detect_agent(client, service)

    async def analyze_many(self, services: list[AIService]) -> list[AIAgent]:
        results = await asyncio.gather(
            *[self.analyze_service(s) for s in services],
            return_exceptions=True,
        )
        return [r for r in results if isinstance(r, AIAgent)]

    async def _detect_agent(
        self, client: httpx.AsyncClient, service: AIService
    ) -> AIAgent | None:
        framework = service.platform or ""
        capabilities: list[AgentCapability] = []
        tool_chain: list[str] = []
        external_integrations: list[str] = []

        sig = AGENT_FRAMEWORK_SIGNATURES.get(framework)
        if sig:
            capabilities = list(sig.get("capabilities", []))

        if framework == "Flowise":
            await self._analyze_flowise(client, service, capabilities, tool_chain, external_integrations)
        elif framework == "AnythingLLM":
            await self._analyze_anythingllm(client, service, capabilities, external_integrations)

        if not capabilities and not tool_chain:
            return None

        agent = AIAgent(
            service=service,
            agent_name=f"{framework} Agent @ {service.host}:{service.port}",
            framework=framework,
            capabilities=capabilities,
            tool_chain=tool_chain,
            external_integrations=external_integrations,
        )

        agent.findings = self._generate_findings(agent)
        agent.risk_score = self._calculate_risk(agent.findings)
        logger.info(f"[+] AI Agent: {agent.agent_name} — risk score {agent.risk_score:.1f}")
        return agent

    async def _analyze_flowise(
        self,
        client: httpx.AsyncClient,
        service: AIService,
        capabilities: list[AgentCapability],
        tool_chain: list[str],
        integrations: list[str],
    ) -> None:
        try:
            r = await client.get(f"{service.url}/api/v1/tools")
            if r.status_code == 200:
                tools = r.json()
                for tool in tools if isinstance(tools, list) else tools.get("tools", []):
                    name = tool.get("name", "").lower()
                    tool_chain.append(tool.get("name", ""))
                    if "bash" in name or "shell" in name:
                        capabilities.append(AgentCapability.SHELL)
                    if "database" in name or "sql" in name:
                        capabilities.append(AgentCapability.DATABASE)
                    if "file" in name:
                        capabilities.append(AgentCapability.FILE_SYSTEM)
                    if "http" in name or "api" in name:
                        integrations.append(tool.get("name", ""))
        except Exception:
            pass

    async def _analyze_anythingllm(
        self,
        client: httpx.AsyncClient,
        service: AIService,
        capabilities: list[AgentCapability],
        integrations: list[str],
    ) -> None:
        try:
            r = await client.get(f"{service.url}/api/system/env-dump")
            if r.status_code == 200:
                env = r.json()
                if env.get("AgentSerperApiKey"):
                    integrations.append("Serper Search API")
                    capabilities.append(AgentCapability.WEB_BROWSING)
                if env.get("AgentGithubToken"):
                    integrations.append("GitHub API")
                if env.get("StorageDir"):
                    capabilities.append(AgentCapability.FILE_SYSTEM)
        except Exception:
            pass

    def _generate_findings(self, agent: AIAgent) -> list[SecurityFinding]:
        findings = []
        for cap in agent.capabilities:
            if cap in DANGEROUS_CAPABILITY_FINDINGS:
                severity, title, description = DANGEROUS_CAPABILITY_FINDINGS[cap]
                findings.append(SecurityFinding(
                    title=title,
                    description=description,
                    severity=severity,
                    category="Agent Security",
                    asset_id=agent.id,
                    asset_url=agent.service.url,
                    remediation=(
                        "Implement strict input validation and sandboxing. "
                        "Apply principle of least privilege to agent capabilities. "
                        "Monitor agent actions and implement rate limiting."
                    ),
                    mitre_techniques=["T1059", "T1190"],
                    owasp_categories=[
                        "LLM06:2025 - Excessive Agency",
                        "LLM01:2025 - Prompt Injection",
                    ],
                ))
        if len(agent.external_integrations) > 5:
            findings.append(SecurityFinding(
                title="Agent Has Excessive External Integrations",
                description=(
                    f"The agent is connected to {len(agent.external_integrations)} "
                    "external services, increasing attack surface and data exfiltration risk."
                ),
                severity=Severity.MEDIUM,
                category="Attack Surface",
                asset_id=agent.id,
                asset_url=agent.service.url,
                remediation="Audit and remove unused integrations.",
                owasp_categories=["LLM06:2025 - Excessive Agency"],
            ))
        return findings

    def _calculate_risk(self, findings: list[SecurityFinding]) -> float:
        weights = {Severity.CRITICAL: 4.0, Severity.HIGH: 2.5,
                   Severity.MEDIUM: 1.0, Severity.LOW: 0.3, Severity.INFO: 0.0}
        return min(10.0, sum(weights.get(f.severity, 0.0) for f in findings))
