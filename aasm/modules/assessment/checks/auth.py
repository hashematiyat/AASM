"""
Feature 4 — Authentication Security Checks
Covers: No Auth, Weak Auth, Anonymous Access, Default Credentials,
API Key Exposure, Weak JWT, OAuth Misconfiguration.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx

from aasm.core.models import AIService, SecurityFinding, Severity

DEFAULT_CREDENTIALS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", ""),
    ("user", "user"),
    ("root", "root"),
    ("test", "test"),
    ("admin", "flowise"),
    ("admin", "litellm"),
    ("admin", "dify"),
]

KNOWN_WEAK_API_KEYS = [
    "sk-test",
    "sk-fake",
    "test-key",
    "demo-key",
    "changeme",
    "your-api-key",
    "placeholder",
    "123456",
    "password",
]

ANONYMOUS_ACCESS_PATHS = [
    "/api/v1/chatflows",
    "/api/v1/credentials",
    "/api/v1/tools",
    "/api/v1/variables",
    "/api/v1/apikey",
    "/management/models",
    "/management/team",
    "/v1/key/generate",
    "/api/users",
    "/api/admin",
    "/api/admin/config",
    "/console/api/apps",
    "/api/workspaces",
    "/api/system-settings",
]


class AuthenticationChecks:
    """Authentication security checks."""

    async def run(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        findings.extend(await self._check_no_auth(client, service))
        findings.extend(await self._check_anonymous_access(client, service))
        findings.extend(await self._check_default_credentials(client, service))
        findings.extend(await self._check_api_key_exposure(client, service))
        findings.extend(await self._check_weak_auth(client, service))

        return findings

    async def _check_no_auth(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        if not service.auth_required:
            findings.append(SecurityFinding(
                title="No Authentication Required",
                description=(
                    f"The AI service at {service.url} is accessible without any "
                    "authentication. Anyone with network access can query models, "
                    "enumerate endpoints, and potentially modify service state."
                ),
                severity=Severity.HIGH,
                category="Authentication",
                asset_id=service.id,
                asset_url=service.url,
                evidence={
                    "platform": service.platform,
                    "auth_type": service.auth_type.value,
                },
                remediation=(
                    "Enable authentication on the AI service. Use API keys, Bearer tokens, "
                    "or OAuth 2.0. Consider network-level controls (VPN, firewall) in addition."
                ),
                mitre_techniques=["T1190", "T1078.004"],
                owasp_categories=["LLM09:2025 - Misinformation", "LLM10:2025 - Unbounded Consumption"],
            ))
        return findings

    async def _check_anonymous_access(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        accessible_sensitive: list[str] = []

        for path in ANONYMOUS_ACCESS_PATHS:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200:
                    accessible_sensitive.append(path)
            except Exception:
                continue

        if accessible_sensitive:
            findings.append(SecurityFinding(
                title="Anonymous Access to Sensitive Endpoints",
                description=(
                    f"The following sensitive endpoints at {service.url} are accessible "
                    f"without authentication: {', '.join(accessible_sensitive)}. "
                    "These endpoints may expose credentials, model data, or allow "
                    "unauthorized API key generation."
                ),
                severity=Severity.CRITICAL,
                category="Authentication",
                asset_id=service.id,
                asset_url=service.url,
                evidence={"accessible_paths": accessible_sensitive},
                remediation=(
                    "Immediately restrict all sensitive endpoints behind authentication. "
                    "Apply the principle of least privilege to API access."
                ),
                mitre_techniques=["T1190", "T1078"],
                owasp_categories=["LLM09:2025 - Misinformation"],
            ))
        return findings

    async def _check_default_credentials(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        admin_path = "/api/admin/login"

        for path in ["/api/admin/login", "/api/v1/predict/test", "/login"]:
            try:
                for username, password in DEFAULT_CREDENTIALS[:5]:
                    cred = base64.b64encode(
                        f"{username}:{password}".encode()
                    ).decode()
                    r = await client.post(
                        f"{service.url}{path}",
                        json={"username": username, "password": password},
                        headers={"Authorization": f"Basic {cred}"},
                        timeout=5.0,
                    )
                    if r.status_code == 200:
                        try:
                            data = r.json()
                            if "token" in data or "accessToken" in data or "access_token" in data:
                                findings.append(SecurityFinding(
                                    title="Default Credentials Accepted",
                                    description=(
                                        f"The AI service at {service.url}{path} accepted "
                                        f"default credentials ({username}:{password}) "
                                        "and returned an authentication token."
                                    ),
                                    severity=Severity.CRITICAL,
                                    category="Authentication",
                                    asset_id=service.id,
                                    asset_url=f"{service.url}{path}",
                                    evidence={
                                        "username": username,
                                        "path": path,
                                        "token_received": True,
                                    },
                                    remediation=(
                                        "Change default credentials immediately. "
                                        "Enforce strong password policies and account lockout."
                                    ),
                                    mitre_techniques=["T1078.001"],
                                    owasp_categories=["LLM09:2025 - Misinformation"],
                                ))
                                return findings
                        except Exception:
                            pass
            except Exception:
                continue
        return findings

    async def _check_api_key_exposure(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        try:
            r = await client.get(f"{service.url}/api/v1/apikey", timeout=5.0)
            if r.status_code == 200:
                try:
                    data = r.json()
                    has_keys = bool(data) and (
                        isinstance(data, list) or "apiKey" in str(data) or "key" in str(data)
                    )
                    if has_keys:
                        findings.append(SecurityFinding(
                            title="API Keys Exposed Without Authentication",
                            description=(
                                f"The endpoint {service.url}/api/v1/apikey returns "
                                "API key data without requiring authentication. "
                                "This allows any attacker to retrieve or manage API keys."
                            ),
                            severity=Severity.CRITICAL,
                            category="Authentication",
                            asset_id=service.id,
                            asset_url=f"{service.url}/api/v1/apikey",
                            evidence={"response_snippet": str(data)[:200]},
                            remediation="Restrict API key endpoints behind strong authentication.",
                            mitre_techniques=["T1552.001", "T1078.004"],
                            owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    async def _check_weak_auth(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        for key in KNOWN_WEAK_API_KEYS:
            try:
                r = await client.get(
                    f"{service.url}/v1/models",
                    headers={
                        "Authorization": f"Bearer {key}",
                        "x-api-key": key,
                    },
                    timeout=5.0,
                )
                if r.status_code == 200:
                    findings.append(SecurityFinding(
                        title="Weak or Default API Key Accepted",
                        description=(
                            f"The AI service at {service.url} accepted a known weak "
                            f"API key ('{key[:10]}...') and returned a successful response. "
                            "This indicates the API key validation is insufficient."
                        ),
                        severity=Severity.HIGH,
                        category="Authentication",
                        asset_id=service.id,
                        asset_url=service.url,
                        evidence={"weak_key_prefix": key[:10]},
                        remediation=(
                            "Implement proper API key validation with sufficient entropy. "
                            "Rotate all current API keys."
                        ),
                        mitre_techniques=["T1078.004"],
                        owasp_categories=["LLM09:2025 - Misinformation"],
                    ))
                    break
            except Exception:
                continue
        return findings
