"""
Feature 4 — Authorization Security Checks
Covers: Broken Access Control, Missing Authorization,
Role Misconfiguration, Privilege Escalation.
"""

from __future__ import annotations

import httpx

from aasm.core.models import AIService, SecurityFinding, Severity

PRIVILEGED_PATHS: list[dict[str, str]] = [
    {"path": "/api/admin",           "description": "Admin panel access"},
    {"path": "/api/admin/config",    "description": "Admin config modification"},
    {"path": "/api/admin/users",     "description": "User management"},
    {"path": "/api/users",           "description": "User enumeration"},
    {"path": "/management/models",   "description": "Model management operations"},
    {"path": "/management/team",     "description": "Team/permission management"},
    {"path": "/v1/key/generate",     "description": "API key generation"},
    {"path": "/api/v1/credentials",  "description": "Credential management"},
    {"path": "/api/v1/variables",    "description": "Variable listing"},
    {"path": "/console/api/setup",   "description": "Setup/initialization endpoint"},
    {"path": "/api/workspaces",      "description": "Workspace management"},
    {"path": "/api/system-settings", "description": "System settings"},
]

IDOR_TEST_IDS = ["1", "2", "3", "0", "admin", "root", "null", "undefined"]


class AuthorizationChecks:
    """Authorization security checks."""

    async def run(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        findings.extend(await self._check_broken_access_control(client, service))
        findings.extend(await self._check_missing_authorization(client, service))
        findings.extend(await self._check_privilege_escalation(client, service))

        return findings

    async def _check_broken_access_control(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        exposed: list[dict[str, str]] = []

        for entry in PRIVILEGED_PATHS:
            path = entry["path"]
            desc = entry["description"]
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200:
                    exposed.append({"path": path, "description": desc})
            except Exception:
                continue

        if exposed:
            paths_str = ", ".join(e["path"] for e in exposed)
            findings.append(SecurityFinding(
                title="Broken Access Control — Privileged Endpoints Exposed",
                description=(
                    f"The following privileged endpoints at {service.url} are accessible "
                    f"without proper authorization: {paths_str}. "
                    "An attacker can enumerate users, manage models, generate API keys, "
                    "or modify system configuration."
                ),
                severity=Severity.CRITICAL,
                category="Authorization",
                asset_id=service.id,
                asset_url=service.url,
                evidence={"exposed_endpoints": exposed},
                remediation=(
                    "Implement role-based access control (RBAC). Ensure all administrative "
                    "and management endpoints require authentication and appropriate authorization."
                ),
                mitre_techniques=["T1078", "T1190"],
                owasp_categories=["LLM09:2025 - Misinformation"],
            ))
        return findings

    async def _check_missing_authorization(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        model_path = "/v1/models"
        try:
            r = await client.get(
                f"{service.url}{model_path}",
                headers={"Authorization": "Bearer invalid_token_xyz_123"},
                timeout=5.0,
            )
            if r.status_code == 200:
                findings.append(SecurityFinding(
                    title="Authorization Not Enforced — Invalid Token Accepted",
                    description=(
                        f"The endpoint {service.url}{model_path} returned HTTP 200 when "
                        "presented with a clearly invalid authorization token. "
                        "The service is not properly validating authentication tokens."
                    ),
                    severity=Severity.HIGH,
                    category="Authorization",
                    asset_id=service.id,
                    asset_url=f"{service.url}{model_path}",
                    evidence={"invalid_token_accepted": True},
                    remediation=(
                        "Implement proper token validation on all protected endpoints. "
                        "Reject requests with invalid, expired, or malformed tokens."
                    ),
                    mitre_techniques=["T1078.004"],
                    owasp_categories=["LLM09:2025 - Misinformation"],
                ))
        except Exception:
            pass
        return findings

    async def _check_privilege_escalation(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        idor_exposed: list[str] = []

        for user_id in IDOR_TEST_IDS[:3]:
            for path_template in ["/api/users/{id}", "/api/v1/users/{id}"]:
                path = path_template.format(id=user_id)
                try:
                    r = await client.get(f"{service.url}{path}", timeout=4.0)
                    if r.status_code == 200:
                        idor_exposed.append(path)
                except Exception:
                    continue

        if idor_exposed:
            findings.append(SecurityFinding(
                title="Potential IDOR — User Records Accessible Without Auth",
                description=(
                    f"The following user-specific endpoints at {service.url} returned "
                    f"HTTP 200 without authentication: {', '.join(idor_exposed)}. "
                    "This may indicate an Insecure Direct Object Reference (IDOR) vulnerability."
                ),
                severity=Severity.HIGH,
                category="Authorization",
                asset_id=service.id,
                asset_url=service.url,
                evidence={"accessible_user_paths": idor_exposed},
                remediation=(
                    "Implement proper object-level authorization. Verify that the requesting "
                    "user has permission to access each resource before returning data."
                ),
                mitre_techniques=["T1078"],
                owasp_categories=["LLM09:2025 - Misinformation"],
            ))
        return findings
