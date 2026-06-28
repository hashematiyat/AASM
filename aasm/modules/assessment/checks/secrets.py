"""
Feature 4 — Secret Detection Checks
Detects exposed API keys, tokens, database credentials, and cloud secrets
in HTTP responses, error pages, and configuration endpoints.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from aasm.core.models import AIService, SecurityFinding, Severity

SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "OpenAI API Key",
        "pattern": re.compile(r'sk-[A-Za-z0-9]{32,64}'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Anthropic API Key",
        "pattern": re.compile(r'sk-ant-[A-Za-z0-9\-]{32,64}'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "AWS Secret Key",
        "pattern": re.compile(r'[A-Za-z0-9/+]{40}(?=[^A-Za-z0-9/+]|$)'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Azure Storage Key",
        "pattern": re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{88}=='),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "GitHub Actions Token",
        "pattern": re.compile(r'ghs_[A-Za-z0-9]{36}'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "GitLab Token",
        "pattern": re.compile(r'glpat-[A-Za-z0-9\-]{20}'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Slack Bot Token",
        "pattern": re.compile(r'xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Slack Webhook",
        "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Discord Token",
        "pattern": re.compile(r'[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Stripe Test Key",
        "pattern": re.compile(r'sk_test_[A-Za-z0-9]{24,}'),
        "severity": Severity.MEDIUM,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Database Credentials (URL)",
        "pattern": re.compile(r'(?:postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@[^/\s]+'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Private Key Block",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "severity": Severity.CRITICAL,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]*'),
        "severity": Severity.MEDIUM,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "HuggingFace Token",
        "pattern": re.compile(r'hf_[A-Za-z0-9]{32,}'),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
    {
        "name": "Generic Secret Assignment",
        "pattern": re.compile(
            r'(?:secret|password|passwd|api_key|apikey|token|access_key)\s*[=:]\s*["\']?([A-Za-z0-9\-_.+/!@#$%^&*]{16,})["\']?',
            re.IGNORECASE,
        ),
        "severity": Severity.HIGH,
        "owasp": "LLM02:2025 - Sensitive Information Disclosure",
    },
]

SCAN_PATHS = [
    "/",
    "/api/config",
    "/api/admin/config",
    "/api/v1/config",
    "/api/system-settings",
    "/openapi.json",
    "/swagger.json",
    "/metrics",
    "/info",
    "/health",
    "/api/version",
]


class SecretsChecks:
    """Secrets detection checks across HTTP responses."""

    async def run(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        for path in SCAN_PATHS:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200 and len(r.content) > 0:
                    path_findings = self._scan_body(r.text, service, path)
                    findings.extend(path_findings)
            except Exception:
                continue

        return findings

    def _scan_body(
        self, body: str, service: AIService, source_path: str
    ) -> list[SecurityFinding]:
        findings = []
        already_found: set[str] = set()

        for secret_def in SECRET_PATTERNS:
            pattern: re.Pattern = secret_def["pattern"]
            matches = pattern.findall(body)

            for match in matches:
                secret_sample = match[:20] if isinstance(match, str) else str(match)[:20]
                dedup_key = f"{secret_def['name']}:{source_path}"
                if dedup_key in already_found:
                    continue
                already_found.add(dedup_key)

                findings.append(SecurityFinding(
                    title=f"Secret Exposed in HTTP Response — {secret_def['name']}",
                    description=(
                        f"A {secret_def['name']} pattern was detected in the HTTP response "
                        f"body at {service.url}{source_path}. Exposed secrets allow "
                        "unauthorized access to connected services and systems."
                    ),
                    severity=secret_def["severity"],
                    category="Secrets",
                    asset_id=service.id,
                    asset_url=f"{service.url}{source_path}",
                    evidence={
                        "secret_type": secret_def["name"],
                        "source_path": source_path,
                        "sample": f"{secret_sample}...[REDACTED]",
                    },
                    remediation=(
                        f"Immediately rotate the exposed {secret_def['name']}. "
                        "Remove secrets from HTTP responses. "
                        "Use environment variables or a secrets manager (Vault, AWS Secrets Manager). "
                        "Audit access logs to determine if the secret was already misused."
                    ),
                    mitre_techniques=["T1552.001"],
                    owasp_categories=[secret_def["owasp"]],
                ))

        return findings
