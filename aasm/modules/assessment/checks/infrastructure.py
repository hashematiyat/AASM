"""
Feature 4 — Infrastructure Security Checks
Covers: Metrics Exposure, Debug Mode, Swagger/OpenAPI Exposure,
Admin Panels, Health Endpoints, Directory Listing,
Docker API Exposure, Kubernetes Dashboard Exposure.
"""

from __future__ import annotations

import httpx

from aasm.core.models import AIService, SecurityFinding, Severity

SWAGGER_PATHS = [
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api/docs",
]

OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/openapi.yaml",
    "/api/schema",
]

DOCKER_API_PATHS = [
    "/_ping",
    "/info",
    "/version",
    "/containers/json",
    "/images/json",
]

K8S_PATHS = [
    "/api",
    "/api/v1",
    "/apis",
    "/api/v1/namespaces",
]

DEBUG_INDICATORS = [
    "traceback", "stack trace", "debug=true",
    "werkzeug debugger", "flask debugger", "fastapi debug",
    "exception details", "sql query", "sqlalchemy",
]

DIR_LISTING_INDICATORS = [
    "index of /", "directory listing", "apache server at",
    "parent directory", "last modified",
]

ADMIN_PATHS = [
    "/admin",
    "/api/admin",
    "/api/admin/config",
    "/api/admin/users",
    "/admin/login",
    "/management",
    "/dashboard",
    "/console",
]


class InfrastructureChecks:
    """Infrastructure security checks."""

    async def run(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        findings.extend(await self._check_metrics_exposure(client, service))
        findings.extend(await self._check_debug_mode(client, service))
        findings.extend(await self._check_swagger_exposure(client, service))
        findings.extend(await self._check_openapi_exposure(client, service))
        findings.extend(await self._check_admin_panels(client, service))
        findings.extend(await self._check_directory_listing(client, service))
        findings.extend(await self._check_docker_api(client, service))
        findings.extend(await self._check_kubernetes_dashboard(client, service))

        return findings

    async def _check_metrics_exposure(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        try:
            r = await client.get(f"{service.url}/metrics", timeout=5.0)
            if r.status_code == 200 and ("# HELP" in r.text or "# TYPE" in r.text):
                content_preview = r.text[:500]
                findings.append(SecurityFinding(
                    title="Prometheus Metrics Exposed Without Authentication",
                    description=(
                        f"The /metrics endpoint at {service.url}/metrics returns Prometheus "
                        "metrics without authentication. This leaks operational intelligence "
                        "including model names, request rates, latency, GPU usage, and "
                        "error patterns — valuable for targeted attacks."
                    ),
                    severity=Severity.MEDIUM,
                    category="Infrastructure",
                    asset_id=service.id,
                    asset_url=f"{service.url}/metrics",
                    evidence={"content_preview": content_preview},
                    remediation=(
                        "Restrict /metrics to internal network access only. "
                        "Add authentication if external access is required. "
                        "Consider using a Prometheus push gateway behind an authenticated proxy."
                    ),
                    owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
                ))
        except Exception:
            pass
        return findings

    async def _check_debug_mode(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        for path in ["/", "/api", "/health"]:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                body = r.text.lower()
                if any(ind in body for ind in DEBUG_INDICATORS):
                    findings.append(SecurityFinding(
                        title="Debug Mode Enabled in Production",
                        description=(
                            f"The AI service at {service.url}{path} appears to be running "
                            "with debug mode enabled. Debug responses can expose stack traces, "
                            "internal configuration, SQL queries, and secrets."
                        ),
                        severity=Severity.HIGH,
                        category="Infrastructure",
                        asset_id=service.id,
                        asset_url=f"{service.url}{path}",
                        evidence={"debug_indicator": [i for i in DEBUG_INDICATORS if i in body][:3]},
                        remediation=(
                            "Disable debug mode in production. "
                            "Set DEBUG=False and configure proper error handling. "
                            "Never expose stack traces to end users."
                        ),
                        owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
                    ))
                    break
            except Exception:
                continue
        return findings

    async def _check_swagger_exposure(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        accessible = []
        for path in SWAGGER_PATHS:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower()):
                    accessible.append(path)
            except Exception:
                continue

        if accessible:
            findings.append(SecurityFinding(
                title="Swagger/API Documentation Exposed",
                description=(
                    f"Interactive API documentation (Swagger UI / ReDoc) is publicly "
                    f"accessible at {service.url}: {', '.join(accessible)}. "
                    "This exposes the complete API surface, enabling attackers to "
                    "systematically enumerate and test all endpoints."
                ),
                severity=Severity.MEDIUM,
                category="Infrastructure",
                asset_id=service.id,
                asset_url=service.url,
                evidence={"accessible_docs": accessible},
                remediation=(
                    "Restrict API documentation to internal networks or authenticated users. "
                    "Disable interactive docs in production if not needed."
                ),
                owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
            ))
        return findings

    async def _check_openapi_exposure(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        for path in OPENAPI_PATHS:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if "paths" in data and "info" in data:
                            path_count = len(data.get("paths", {}))
                            title = data.get("info", {}).get("title", "Unknown")
                            findings.append(SecurityFinding(
                                title="OpenAPI Specification Publicly Accessible",
                                description=(
                                    f"The OpenAPI specification for '{title}' is accessible at "
                                    f"{service.url}{path}, exposing {path_count} API endpoints, "
                                    "request/response schemas, authentication requirements, "
                                    "and server configuration."
                                ),
                                severity=Severity.LOW,
                                category="Infrastructure",
                                asset_id=service.id,
                                asset_url=f"{service.url}{path}",
                                evidence={"title": title, "path_count": path_count},
                                remediation=(
                                    "Consider restricting OpenAPI specs to authenticated users "
                                    "or internal networks. Remove sensitive examples from specs."
                                ),
                                owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                continue
        return findings

    async def _check_admin_panels(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        exposed = []
        for path in ADMIN_PATHS:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200:
                    exposed.append(path)
            except Exception:
                continue

        if exposed:
            findings.append(SecurityFinding(
                title="Admin Panel Accessible Without Authentication",
                description=(
                    f"Administrative interfaces at {service.url} are accessible without "
                    f"authentication: {', '.join(exposed)}. Admin panels typically allow "
                    "full control over service configuration, users, and data."
                ),
                severity=Severity.CRITICAL,
                category="Infrastructure",
                asset_id=service.id,
                asset_url=service.url,
                evidence={"exposed_admin_paths": exposed},
                remediation=(
                    "Immediately restrict all admin interfaces to authenticated admin users. "
                    "Place admin panels on separate internal-only endpoints. "
                    "Implement IP allowlisting for admin access."
                ),
                mitre_techniques=["T1190", "T1078"],
                owasp_categories=["LLM09:2025 - Misinformation"],
            ))
        return findings

    async def _check_directory_listing(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        for path in ["/static/", "/assets/", "/public/", "/files/"]:
            try:
                r = await client.get(f"{service.url}{path}", timeout=5.0)
                if r.status_code == 200:
                    body = r.text.lower()
                    if any(ind in body for ind in DIR_LISTING_INDICATORS):
                        findings.append(SecurityFinding(
                            title="Directory Listing Enabled",
                            description=(
                                f"Directory listing is enabled at {service.url}{path}. "
                                "This exposes file structure, potentially leaking source code, "
                                "configuration files, or sensitive documents."
                            ),
                            severity=Severity.MEDIUM,
                            category="Infrastructure",
                            asset_id=service.id,
                            asset_url=f"{service.url}{path}",
                            evidence={"path": path},
                            remediation=(
                                "Disable directory listing in your web server configuration. "
                                "For nginx: add 'autoindex off;'. For Apache: add 'Options -Indexes'."
                            ),
                            owasp_categories=["LLM02:2025 - Sensitive Information Disclosure"],
                        ))
                        break
            except Exception:
                continue
        return findings

    async def _check_docker_api(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        try:
            r = await client.get(f"{service.url}/_ping", timeout=5.0)
            if r.status_code == 200 and r.text.strip().lower() == "ok":
                version_data = await client.get(f"{service.url}/version", timeout=5.0)
                if version_data.status_code == 200:
                    try:
                        data = version_data.json()
                        if "DockerVersion" in data or "ApiVersion" in data:
                            findings.append(SecurityFinding(
                                title="Docker API Exposed Without Authentication",
                                description=(
                                    f"The Docker daemon API appears to be exposed at {service.url}. "
                                    "An unauthenticated Docker API allows full container lifecycle "
                                    "control, image access, and potential host escape."
                                ),
                                severity=Severity.CRITICAL,
                                category="Infrastructure",
                                asset_id=service.id,
                                asset_url=service.url,
                                evidence={"docker_version": data.get("Version", "")},
                                remediation=(
                                    "Never expose the Docker daemon socket or API without "
                                    "TLS client certificate authentication. "
                                    "Use a dedicated reverse proxy with authentication."
                                ),
                                mitre_techniques=["T1610", "T1611"],
                                owasp_categories=["LLM06:2025 - Excessive Agency"],
                            ))
                    except Exception:
                        pass
        except Exception:
            pass
        return findings

    async def _check_kubernetes_dashboard(
        self, client: httpx.AsyncClient, service: AIService
    ) -> list[SecurityFinding]:
        findings = []
        try:
            r = await client.get(f"{service.url}/api/v1/namespaces", timeout=5.0)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "items" in data and "apiVersion" in data:
                        findings.append(SecurityFinding(
                            title="Kubernetes API Server Accessible Without Authentication",
                            description=(
                                f"The Kubernetes API server at {service.url} returns namespace "
                                "listings without authentication. This allows full cluster "
                                "enumeration and potentially arbitrary workload deployment."
                            ),
                            severity=Severity.CRITICAL,
                            category="Infrastructure",
                            asset_id=service.id,
                            asset_url=service.url,
                            evidence={"namespace_count": len(data.get("items", []))},
                            remediation=(
                                "Disable anonymous access to the Kubernetes API. "
                                "Enable RBAC and require authentication for all API calls. "
                                "Never expose the API server publicly."
                            ),
                            mitre_techniques=["T1613"],
                            owasp_categories=["LLM06:2025 - Excessive Agency"],
                        ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings
