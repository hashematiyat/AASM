"""
Feature 1 — Deep Fingerprinting Extension
Professional AI-oriented fingerprinting engine.
Produces a rich DeepFingerprint object with network, service, security,
AI, and performance information — similar to Nmap's -sV -sC but AI-aware.
Integrates cleanly alongside the existing FingerprintEngine without replacing it.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from aasm.core.logger import get_logger
from aasm.core.models import AIService

logger = get_logger("fingerprint.deep")


@dataclass
class NetworkFingerprint:
    """Network-layer fingerprint information."""
    protocol: str = "http"
    http_version: str = "unknown"
    tls_version: str | None = None
    alpn_protocols: list[str] = field(default_factory=list)
    http2_supported: bool = False
    http3_supported: bool = False
    websocket_supported: bool = False
    grpc_detected: bool = False
    compression: list[str] = field(default_factory=list)
    keep_alive: bool = False
    server_banner: str = ""


@dataclass
class ServiceFingerprint:
    """Service / application-layer fingerprint information."""
    product_name: str = ""
    vendor: str = ""
    version: str = ""
    build_number: str = ""
    framework: str = ""
    deployment_type: str = ""
    reverse_proxy: str = ""
    openapi_title: str = ""
    openapi_version: str = ""


@dataclass
class SecurityFingerprint:
    """Security posture fingerprint."""
    auth_required: bool = False
    auth_type: str = "none"
    jwt_in_use: bool = False
    oauth_in_use: bool = False
    api_key_in_use: bool = False
    cors_policy: str = ""
    cors_wildcard: bool = False
    security_headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    rate_limiting: bool = False
    rate_limit_header: str = ""
    allowed_methods: list[str] = field(default_factory=list)


@dataclass
class AICapabilityFingerprint:
    """AI capabilities fingerprint."""
    models: list[str] = field(default_factory=list)
    running_models: list[str] = field(default_factory=list)
    embedding_models: list[str] = field(default_factory=list)
    context_window: int | None = None
    quantization: str | None = None
    streaming_supported: bool = False
    function_calling: bool = False
    tool_calling: bool = False
    mcp_supported: bool = False
    agent_supported: bool = False
    image_generation: bool = False
    audio_transcription: bool = False
    multimodal: bool = False


@dataclass
class PerformanceFingerprint:
    """Performance characteristics fingerprint."""
    response_time_ms: float | None = None
    average_latency_ms: float | None = None
    concurrent_requests_supported: int | None = None
    gpu_enabled: bool = False
    gpu_memory_utilization: float | None = None


@dataclass
class DeepFingerprint:
    """Comprehensive AI service fingerprint combining all dimensions."""
    service_url: str = ""
    network: NetworkFingerprint = field(default_factory=NetworkFingerprint)
    service: ServiceFingerprint = field(default_factory=ServiceFingerprint)
    security: SecurityFingerprint = field(default_factory=SecurityFingerprint)
    ai_capabilities: AICapabilityFingerprint = field(default_factory=AICapabilityFingerprint)
    performance: PerformanceFingerprint = field(default_factory=PerformanceFingerprint)
    raw_headers: dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_url": self.service_url,
            "network": {
                "protocol": self.network.protocol,
                "http_version": self.network.http_version,
                "tls_version": self.network.tls_version,
                "alpn_protocols": self.network.alpn_protocols,
                "http2_supported": self.network.http2_supported,
                "websocket_supported": self.network.websocket_supported,
                "grpc_detected": self.network.grpc_detected,
                "compression": self.network.compression,
                "keep_alive": self.network.keep_alive,
                "server_banner": self.network.server_banner,
            },
            "service": {
                "product_name": self.service.product_name,
                "vendor": self.service.vendor,
                "version": self.service.version,
                "build_number": self.service.build_number,
                "framework": self.service.framework,
                "deployment_type": self.service.deployment_type,
                "reverse_proxy": self.service.reverse_proxy,
            },
            "security": {
                "auth_required": self.security.auth_required,
                "auth_type": self.security.auth_type,
                "jwt_in_use": self.security.jwt_in_use,
                "oauth_in_use": self.security.oauth_in_use,
                "api_key_in_use": self.security.api_key_in_use,
                "cors_policy": self.security.cors_policy,
                "cors_wildcard": self.security.cors_wildcard,
                "security_headers": self.security.security_headers,
                "missing_headers": self.security.missing_headers,
                "rate_limiting": self.security.rate_limiting,
                "allowed_methods": self.security.allowed_methods,
            },
            "ai_capabilities": {
                "models": self.ai_capabilities.models,
                "running_models": self.ai_capabilities.running_models,
                "embedding_models": self.ai_capabilities.embedding_models,
                "context_window": self.ai_capabilities.context_window,
                "quantization": self.ai_capabilities.quantization,
                "streaming_supported": self.ai_capabilities.streaming_supported,
                "function_calling": self.ai_capabilities.function_calling,
                "tool_calling": self.ai_capabilities.tool_calling,
                "mcp_supported": self.ai_capabilities.mcp_supported,
                "agent_supported": self.ai_capabilities.agent_supported,
            },
            "performance": {
                "response_time_ms": self.performance.response_time_ms,
                "average_latency_ms": self.performance.average_latency_ms,
                "gpu_enabled": self.performance.gpu_enabled,
            },
            "confidence": self.confidence,
        }


SECURITY_HEADERS_TO_CHECK = [
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
]

REVERSE_PROXY_HEADERS: dict[str, str] = {
    "x-nginx-proxy": "nginx",
    "via": "proxy",
    "x-forwarded-by": "proxy",
    "server": "",
    "x-powered-by": "",
    "x-envoy-upstream-service-time": "Envoy/Istio",
    "x-kong-upstream-latency": "Kong",
    "x-traefik-request-id": "Traefik",
    "x-caddy-trace-id": "Caddy",
}

KNOWN_PROXY_VALUES: dict[str, str] = {
    "nginx": "nginx",
    "apache": "Apache",
    "caddy": "Caddy",
    "traefik": "Traefik",
    "envoy": "Envoy",
    "kong": "Kong",
    "haproxy": "HAProxy",
    "cloudflare": "Cloudflare",
    "aws": "AWS",
}


class DeepFingerprintEngine:
    """
    Produces a rich DeepFingerprint by combining network probing, header
    analysis, JSON introspection, and AI capability detection.
    Works alongside the existing FingerprintEngine — call both for maximum coverage.
    """

    def __init__(self, timeout: float = 10.0, verify_ssl: bool = False) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def fingerprint(self, service: AIService) -> DeepFingerprint:
        """Produce a DeepFingerprint for the given service."""
        fp = DeepFingerprint(service_url=service.url)
        t0 = time.monotonic()

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            follow_redirects=True,
            http2=True,
        ) as client:
            await asyncio.gather(
                self._fingerprint_network(client, service, fp),
                self._fingerprint_service(client, service, fp),
                self._fingerprint_security(client, service, fp),
                self._fingerprint_ai(client, service, fp),
            )

        elapsed = (time.monotonic() - t0) * 1000
        fp.performance.response_time_ms = elapsed

        self._measure_average_latency(fp)
        self._compute_confidence(fp, service)
        self._store_in_metadata(service, fp)

        logger.info(
            f"Deep fingerprint complete for {service.url} "
            f"(confidence={fp.confidence:.0%})"
        )
        return fp

    async def fingerprint_many(
        self, services: list[AIService]
    ) -> list[DeepFingerprint]:
        """Fingerprint multiple services concurrently."""
        return list(await asyncio.gather(*[self.fingerprint(s) for s in services]))

    async def _fingerprint_network(
        self,
        client: httpx.AsyncClient,
        service: AIService,
        fp: DeepFingerprint,
    ) -> None:
        """Probe network-layer characteristics."""
        try:
            r = await client.get(service.url, timeout=self.timeout)

            fp.network.protocol = "https" if service.tls else "http"
            fp.network.server_banner = r.headers.get("server", "")
            fp.network.keep_alive = (
                r.headers.get("connection", "").lower() == "keep-alive"
                or "keep-alive" in r.headers.get("keep-alive", "")
            )

            ce = r.headers.get("content-encoding", "")
            if ce:
                fp.network.compression = [c.strip() for c in ce.split(",")]

            via = r.headers.get("via", "")
            if via:
                fp.network.http_version = via.split(" ")[0] if " " in via else "unknown"

            upgrade = r.headers.get("upgrade", "").lower()
            fp.network.websocket_supported = "websocket" in upgrade

            content_type = r.headers.get("content-type", "")
            if "application/grpc" in content_type:
                fp.network.grpc_detected = True

            alpn = r.headers.get("alpn", "") or r.headers.get("alt-svc", "")
            if alpn:
                fp.network.alpn_protocols = [p.strip() for p in alpn.split(",")]
                fp.network.http2_supported = "h2" in alpn
                fp.network.http3_supported = "h3" in alpn

            fp.raw_headers = dict(r.headers)

        except Exception as e:
            logger.debug(f"Network fingerprint error at {service.url}: {e}")

    async def _fingerprint_service(
        self,
        client: httpx.AsyncClient,
        service: AIService,
        fp: DeepFingerprint,
    ) -> None:
        """Fingerprint service identity."""
        fp.service.product_name = service.platform or ""
        fp.service.version = service.version or ""

        try:
            r = await client.get(service.url, timeout=self.timeout)
            server = r.headers.get("server", "").lower()
            fp.service.framework = self._detect_framework_from_server(server)
            fp.service.reverse_proxy = self._detect_reverse_proxy(r.headers)
            fp.service.deployment_type = self._detect_deployment_type(r.headers, server)

            x_powered = r.headers.get("x-powered-by", "")
            if x_powered and not fp.service.framework:
                fp.service.framework = x_powered

        except Exception as e:
            logger.debug(f"Service fingerprint error at {service.url}: {e}")

        try:
            r = await client.get(f"{service.url}/openapi.json", timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                info = data.get("info", {})
                fp.service.openapi_title = info.get("title", "")
                fp.service.openapi_version = info.get("version", "")
                if not fp.service.version and fp.service.openapi_version:
                    fp.service.version = fp.service.openapi_version
        except Exception:
            pass

        vendor_map = {
            "Ollama": "Ollama Inc.",
            "Open WebUI": "Open WebUI Community",
            "LiteLLM": "BerriAI",
            "vLLM": "vLLM Project",
            "LM Studio": "LM Studio",
            "Flowise": "FlowiseAI",
            "Dify": "Dify AI",
            "Langflow": "Langflow",
            "AnythingLLM": "Mintplex Labs",
            "LocalAI": "LocalAI Community",
            "HuggingFace TGI": "Hugging Face",
            "FastChat": "LMSYS",
            "Text Generation WebUI": "oobabooga",
            "CrewAI": "CrewAI Inc.",
            "AutoGen": "Microsoft Research",
            "LangGraph": "LangChain Inc.",
            "OpenHands": "All Hands AI",
        }
        fp.service.vendor = vendor_map.get(fp.service.product_name, "unknown")

    async def _fingerprint_security(
        self,
        client: httpx.AsyncClient,
        service: AIService,
        fp: DeepFingerprint,
    ) -> None:
        """Analyse security posture from HTTP responses."""
        fp.security.auth_required = service.auth_required
        fp.security.auth_type = service.auth_type.value

        try:
            r = await client.get(service.url, timeout=self.timeout)

            www_auth = r.headers.get("www-authenticate", "").lower()
            auth_hdr = r.headers.get("authorization", "").lower()
            fp.security.jwt_in_use = "bearer" in www_auth or "jwt" in auth_hdr
            fp.security.oauth_in_use = "oauth" in www_auth
            fp.security.api_key_in_use = (
                "api-key" in r.headers or "x-api-key" in r.headers
            )

            cors = r.headers.get("access-control-allow-origin", "")
            fp.security.cors_policy = cors
            fp.security.cors_wildcard = cors == "*"

            found_sec_headers: dict[str, str] = {}
            missing: list[str] = []
            for h in SECURITY_HEADERS_TO_CHECK:
                val = r.headers.get(h, "")
                if val:
                    found_sec_headers[h] = val
                else:
                    missing.append(h)
            fp.security.security_headers = found_sec_headers
            fp.security.missing_headers = missing

            rate_headers = [
                "x-ratelimit-limit",
                "x-rate-limit-limit",
                "ratelimit-limit",
                "x-ratelimit-requests",
            ]
            for rh in rate_headers:
                if rh in r.headers:
                    fp.security.rate_limiting = True
                    fp.security.rate_limit_header = r.headers[rh]
                    break

        except Exception as e:
            logger.debug(f"Security fingerprint error at {service.url}: {e}")

        try:
            r = await client.options(service.url, timeout=5.0)
            allow = r.headers.get("allow", "") or r.headers.get("access-control-allow-methods", "")
            if allow:
                fp.security.allowed_methods = [m.strip() for m in allow.split(",")]
        except Exception:
            pass

    async def _fingerprint_ai(
        self,
        client: httpx.AsyncClient,
        service: AIService,
        fp: DeepFingerprint,
    ) -> None:
        """Probe AI-specific capabilities."""
        fp.ai_capabilities.models = [m.name for m in service.models]

        try:
            r = await client.get(f"{service.url}/api/ps", timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                running = data.get("models", [])
                fp.ai_capabilities.running_models = [
                    m.get("name", "") for m in running if isinstance(m, dict)
                ]
        except Exception:
            pass

        try:
            r = await client.get(f"{service.url}/v1/models", timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                for m in data.get("data", []):
                    if isinstance(m, dict):
                        mid = m.get("id", "")
                        if "embed" in mid.lower() or "embedding" in mid.lower():
                            fp.ai_capabilities.embedding_models.append(mid)
        except Exception:
            pass

        for model in service.models:
            raw = model.raw
            ctx = raw.get("context_length") or raw.get("context_size") or raw.get("num_ctx")
            if ctx:
                try:
                    fp.ai_capabilities.context_window = int(ctx)
                except Exception:
                    pass
            quant = raw.get("quantization") or raw.get("quantization_level")
            if quant:
                fp.ai_capabilities.quantization = str(quant)

        streaming_paths = ["/api/generate", "/api/chat", "/generate_stream", "/v1/chat/completions"]
        for svc_ep in service.endpoints:
            if svc_ep in streaming_paths:
                fp.ai_capabilities.streaming_supported = True
                break

        tool_paths = ["/v1/chat/completions"]
        function_paths = ["/v1/chat/completions"]
        for ep in service.endpoints:
            if ep in tool_paths:
                fp.ai_capabilities.tool_calling = True
            if ep in function_paths:
                fp.ai_capabilities.function_calling = True

        mcp_indicators = ["/sse", "/mcp", "/mcp/sse"]
        for ep in service.endpoints:
            if ep in mcp_indicators:
                fp.ai_capabilities.mcp_supported = True
                break

        agent_platforms = {"CrewAI", "AutoGen", "LangGraph", "OpenHands", "Flowise", "Dify", "Langflow"}
        if service.platform in agent_platforms:
            fp.ai_capabilities.agent_supported = True

        image_paths = ["/v1/images/generations"]
        for ep in service.endpoints:
            if ep in image_paths:
                fp.ai_capabilities.image_generation = True

        audio_paths = ["/v1/audio/transcriptions", "/v1/audio/speech"]
        for ep in service.endpoints:
            if ep in audio_paths:
                fp.ai_capabilities.audio_transcription = True

    def _measure_average_latency(self, fp: DeepFingerprint) -> None:
        if fp.performance.response_time_ms is not None:
            fp.performance.average_latency_ms = fp.performance.response_time_ms

    def _compute_confidence(self, fp: DeepFingerprint, service: AIService) -> None:
        score = 0.0
        total = 0.0

        if fp.service.product_name:
            score += 0.25
        total += 0.25

        if fp.network.server_banner:
            score += 0.15
        total += 0.15

        if fp.service.version and fp.service.version != "unknown":
            score += 0.20
        total += 0.20

        if fp.ai_capabilities.models:
            score += 0.20
        total += 0.20

        if fp.security.security_headers:
            score += 0.10
        total += 0.10

        if fp.network.http_version or fp.network.tls_version:
            score += 0.10
        total += 0.10

        fp.confidence = score / total if total > 0 else 0.0

    def _store_in_metadata(self, service: AIService, fp: DeepFingerprint) -> None:
        service.metadata["deep_fingerprint"] = fp.to_dict()
        if fp.network.server_banner:
            service.metadata["server_banner"] = fp.network.server_banner
        if fp.service.reverse_proxy:
            service.metadata["reverse_proxy"] = fp.service.reverse_proxy
        if fp.service.framework:
            service.metadata["framework"] = fp.service.framework
        if fp.security.cors_wildcard:
            service.tags.append("cors-wildcard")
        if fp.network.grpc_detected:
            service.tags.append("grpc")
        if fp.ai_capabilities.mcp_supported:
            service.tags.append("mcp-enabled")
        if fp.ai_capabilities.agent_supported:
            service.tags.append("agent-enabled")

    def _detect_framework_from_server(self, server: str) -> str:
        if "uvicorn" in server or "fastapi" in server:
            return "FastAPI/Uvicorn"
        if "gunicorn" in server:
            return "Gunicorn"
        if "express" in server:
            return "Express.js"
        if "flask" in server or "werkzeug" in server:
            return "Flask"
        if "django" in server:
            return "Django"
        if "gradio" in server:
            return "Gradio"
        if "ray" in server:
            return "Ray Serve"
        return ""

    def _detect_reverse_proxy(self, headers: httpx.Headers) -> str:
        server = headers.get("server", "").lower()
        for keyword, label in KNOWN_PROXY_VALUES.items():
            if keyword in server:
                return label
        for header_name, label in REVERSE_PROXY_HEADERS.items():
            if header_name in headers:
                if label:
                    return label
        return ""

    def _detect_deployment_type(self, headers: httpx.Headers, server: str) -> str:
        if "cloudflare" in server or "cf-ray" in headers:
            return "Cloud (Cloudflare)"
        if "awselb" in server or "x-amzn-requestid" in headers:
            return "Cloud (AWS)"
        if "gws" in server or "x-goog-" in " ".join(headers.keys()):
            return "Cloud (GCP)"
        if "microsoft" in server or "x-ms-" in " ".join(headers.keys()):
            return "Cloud (Azure)"
        if "docker" in server or "kubernetes" in " ".join(headers.values()):
            return "Container"
        return "Self-hosted"
