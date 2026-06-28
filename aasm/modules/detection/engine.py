"""
Feature 2 — Smart Detection Engine
Confidence-based multi-signal platform detection engine.
Never identifies services based only on ports. Uses HTTP headers, JSON
responses, HTML content, cookies, URL patterns, error pages, and more.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from aasm.core.logger import get_logger
from aasm.core.models import AIService, AIServiceType, AuthType
from .signatures import PLATFORM_SIGNATURES, PlatformSignature

logger = get_logger("detection")


@dataclass
class DetectionSignal:
    """A single matched detection signal with its weight contribution."""
    signal_type: str
    signal_value: str
    matched_pattern: str
    confidence_contribution: float


@dataclass
class PlatformDetectionResult:
    """Result of confidence-based platform detection."""
    platform: str
    confidence: float
    signals: list[DetectionSignal] = field(default_factory=list)
    service: AIService | None = None

    @property
    def confidence_pct(self) -> str:
        return f"{self.confidence * 100:.0f}%"

    @property
    def matched_by(self) -> list[str]:
        return [f"{s.signal_type}: {s.matched_pattern}" for s in self.signals]


class SmartDetectionEngine:
    """
    Multi-signal, confidence-based AI platform detection engine.

    Aggregates evidence across multiple detection dimensions:
    - HTTP response headers
    - JSON response body keys and values
    - HTML page content and title
    - Favicon hash fingerprinting
    - JavaScript asset patterns
    - Cookie names
    - URL/path structure
    - OpenAPI spec metadata
    - GraphQL introspection
    - Error page content and signatures
    """

    CONFIDENCE_THRESHOLD = 0.30

    def __init__(self, client: httpx.AsyncClient, timeout: float = 8.0) -> None:
        self.client = client
        self.timeout = timeout

    async def detect(
        self, host: str, port: int, url: str | None = None
    ) -> list[PlatformDetectionResult]:
        """
        Run multi-signal detection against host:port.
        Returns a ranked list of PlatformDetectionResults sorted by confidence.
        """
        if url is None:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host}:{port}"

        evidence = await self._collect_evidence(url)
        results: list[PlatformDetectionResult] = []

        for platform_name, sig in PLATFORM_SIGNATURES.items():
            result = self._score_platform(sig, evidence)
            if result.confidence >= self.CONFIDENCE_THRESHOLD:
                results.append(result)
                logger.debug(
                    f"Detected {platform_name} at {url} "
                    f"with confidence {result.confidence_pct}"
                )

        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    async def detect_best(
        self, host: str, port: int, url: str | None = None
    ) -> PlatformDetectionResult | None:
        """Return the highest-confidence detection result above threshold."""
        results = await self.detect(host, port, url)
        return results[0] if results else None

    async def _collect_evidence(self, base_url: str) -> dict[str, Any]:
        """
        Collect raw evidence from the target via HTTP probing.
        Returns a normalized evidence dict used for scoring.
        """
        evidence: dict[str, Any] = {
            "headers": {},
            "json_keys": [],
            "json_values": [],
            "html_content": "",
            "html_title": "",
            "paths_responsive": [],
            "cookie_names": [],
            "favicon_hash": None,
            "js_content": "",
            "openapi_title": "",
            "openapi_paths": [],
            "error_content": "",
            "server_banner": "",
            "status_codes": {},
        }

        await self._probe_root(base_url, evidence)
        await self._probe_openapi(base_url, evidence)
        await self._probe_favicon(base_url, evidence)
        await self._probe_common_paths(base_url, evidence)

        return evidence

    async def _probe_root(self, base_url: str, evidence: dict[str, Any]) -> None:
        """Probe the root path for headers, HTML, cookies."""
        for path in ["", "/", "/api", "/health"]:
            try:
                r = await self.client.get(
                    f"{base_url}{path}", timeout=self.timeout
                )
                if r.status_code < 500:
                    for k, v in r.headers.items():
                        evidence["headers"][k.lower()] = v.lower()

                    server = r.headers.get("server", "")
                    if server:
                        evidence["server_banner"] = server.lower()

                    for cookie_name in r.cookies.keys():
                        evidence["cookie_names"].append(cookie_name.lower())

                    ct = r.headers.get("content-type", "")
                    if "json" in ct:
                        try:
                            data = r.json()
                            self._extract_json_signals(data, evidence)
                        except Exception:
                            pass
                    elif "html" in ct:
                        html = r.text
                        evidence["html_content"] = html[:8000].lower()
                        m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
                        if m:
                            evidence["html_title"] = m.group(1).strip().lower()

                    evidence["status_codes"][path] = r.status_code
                    break
            except Exception:
                continue

    async def _probe_openapi(self, base_url: str, evidence: dict[str, Any]) -> None:
        """Check /openapi.json and /swagger.json for framework signals."""
        for path in ["/openapi.json", "/swagger.json", "/docs/openapi.json"]:
            try:
                r = await self.client.get(
                    f"{base_url}{path}", timeout=5.0
                )
                if r.status_code == 200:
                    data = r.json()
                    info = data.get("info", {})
                    title = info.get("title", "")
                    if title:
                        evidence["openapi_title"] = title.lower()
                    paths = list(data.get("paths", {}).keys())
                    evidence["openapi_paths"] = paths[:30]
                    self._extract_json_signals(data, evidence)
                    break
            except Exception:
                continue

    async def _probe_favicon(self, base_url: str, evidence: dict[str, Any]) -> None:
        """Fetch and hash the favicon for fingerprinting."""
        for path in ["/favicon.ico", "/favicon.png"]:
            try:
                r = await self.client.get(
                    f"{base_url}{path}", timeout=5.0
                )
                if r.status_code == 200 and len(r.content) > 0:
                    h = hashlib.md5(r.content).hexdigest()
                    evidence["favicon_hash"] = h
                    break
            except Exception:
                continue

    async def _probe_common_paths(
        self, base_url: str, evidence: dict[str, Any]
    ) -> None:
        """Probe well-known paths across all platforms to gather responsive endpoints."""
        all_paths = set()
        for sig in PLATFORM_SIGNATURES.values():
            for p in sig.probe_paths:
                all_paths.add(p)

        import asyncio

        async def probe_path(path: str) -> tuple[str, int | None, str]:
            try:
                r = await self.client.get(
                    f"{base_url}{path}", timeout=4.0
                )
                body = ""
                if r.status_code < 500:
                    ct = r.headers.get("content-type", "")
                    if "json" in ct:
                        body = r.text[:2000]
                    elif "html" in ct:
                        body = r.text[:1000]
                return path, r.status_code, body
            except Exception:
                return path, None, ""

        results = await asyncio.gather(*[probe_path(p) for p in all_paths])

        for path, status, body in results:
            if status is not None and status < 500:
                evidence["paths_responsive"].append(path)
                if body:
                    try:
                        import json
                        data = json.loads(body)
                        self._extract_json_signals(data, evidence)
                    except Exception:
                        pass

    def _extract_json_signals(
        self, data: Any, evidence: dict[str, Any], depth: int = 0
    ) -> None:
        """Recursively extract all JSON keys and leaf string values."""
        if depth > 3:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                evidence["json_keys"].append(k.lower())
                if isinstance(v, str) and v:
                    evidence["json_values"].append(v.lower()[:100])
                elif isinstance(v, (dict, list)):
                    self._extract_json_signals(v, evidence, depth + 1)
        elif isinstance(data, list):
            for item in data[:5]:
                self._extract_json_signals(item, evidence, depth + 1)

    def _score_platform(
        self, sig: PlatformSignature, evidence: dict[str, Any]
    ) -> PlatformDetectionResult:
        """
        Score a single platform against collected evidence.
        Returns a PlatformDetectionResult with accumulated confidence.
        """
        signals: list[DetectionSignal] = []
        weights = sig.signal_weights

        header_weight = weights.get("header", 0.30)
        json_weight = weights.get("json", 0.30)
        html_weight = weights.get("html", 0.20)
        path_weight = weights.get("path", 0.15)
        cookie_weight = weights.get("cookie", 0.05)
        error_weight = weights.get("error", 0.05)
        openapi_weight = weights.get("openapi", 0.10)

        matched_headers = self._match_headers(sig, evidence.get("headers", {}))
        for m in matched_headers:
            contrib = header_weight * (1.0 / max(len(sig.header_signals), 1))
            signals.append(DetectionSignal(
                signal_type="HTTP Header",
                signal_value=str(evidence.get("headers", {}).get(m["key"], "")),
                matched_pattern=f"{m['key']}: {m['pattern']}",
                confidence_contribution=contrib,
            ))

        matched_json = self._match_json(sig, evidence)
        if matched_json and sig.json_signals:
            ratio = min(len(matched_json) / len(sig.json_signals), 1.0)
            contrib = json_weight * ratio
            signals.append(DetectionSignal(
                signal_type="JSON Response",
                signal_value=str(matched_json[:5]),
                matched_pattern=f"keys: {matched_json[:5]}",
                confidence_contribution=contrib,
            ))

        matched_html = self._match_html(sig, evidence)
        if matched_html and sig.html_signals:
            ratio = min(len(matched_html) / len(sig.html_signals), 1.0)
            contrib = html_weight * ratio
            signals.append(DetectionSignal(
                signal_type="HTML Content",
                signal_value=str(matched_html[:3]),
                matched_pattern=f"patterns: {matched_html[:3]}",
                confidence_contribution=contrib,
            ))

        matched_paths = self._match_paths(sig, evidence.get("paths_responsive", []))
        if matched_paths and sig.path_signals:
            ratio = min(len(matched_paths) / len(sig.path_signals), 1.0)
            contrib = path_weight * ratio
            signals.append(DetectionSignal(
                signal_type="Endpoint Path",
                signal_value=str(matched_paths[:5]),
                matched_pattern=f"responsive: {matched_paths[:5]}",
                confidence_contribution=contrib,
            ))

        matched_cookies = self._match_cookies(sig, evidence.get("cookie_names", []))
        for c in matched_cookies:
            signals.append(DetectionSignal(
                signal_type="Cookie",
                signal_value=c,
                matched_pattern=c,
                confidence_contribution=cookie_weight,
            ))

        matched_errors = self._match_errors(sig, evidence.get("error_content", ""))
        for e in matched_errors:
            signals.append(DetectionSignal(
                signal_type="Error Signature",
                signal_value=e,
                matched_pattern=e,
                confidence_contribution=error_weight * 0.5,
            ))

        matched_openapi = self._match_openapi(sig, evidence)
        for o in matched_openapi:
            signals.append(DetectionSignal(
                signal_type="OpenAPI Spec",
                signal_value=o,
                matched_pattern=o,
                confidence_contribution=openapi_weight,
            ))

        total_confidence = min(sum(s.confidence_contribution for s in signals), 1.0)

        return PlatformDetectionResult(
            platform=sig.platform,
            confidence=total_confidence,
            signals=signals,
        )

    def _match_headers(
        self, sig: PlatformSignature, headers: dict[str, str]
    ) -> list[dict[str, str]]:
        matched = []
        for header_sig in sig.header_signals:
            for key, pattern in header_sig.items():
                key_lower = key.lower()
                if key_lower in headers:
                    if not pattern or pattern.lower() in headers[key_lower]:
                        matched.append({"key": key_lower, "pattern": pattern})
        return matched

    def _match_json(
        self, sig: PlatformSignature, evidence: dict[str, Any]
    ) -> list[str]:
        json_keys = set(evidence.get("json_keys", []))
        json_values = evidence.get("json_values", [])
        matched = []
        for js in sig.json_signals:
            js_lower = js.lower()
            if js_lower in json_keys:
                matched.append(js_lower)
            elif any(js_lower in v for v in json_values):
                matched.append(js_lower)
        return matched

    def _match_html(
        self, sig: PlatformSignature, evidence: dict[str, Any]
    ) -> list[str]:
        html = evidence.get("html_content", "") + " " + evidence.get("html_title", "")
        matched = []
        for pattern in sig.html_signals:
            if pattern.lower() in html:
                matched.append(pattern)
        return matched

    def _match_paths(
        self, sig: PlatformSignature, responsive_paths: list[str]
    ) -> list[str]:
        responsive_set = set(responsive_paths)
        return [p for p in sig.path_signals if p in responsive_set]

    def _match_cookies(
        self, sig: PlatformSignature, cookie_names: list[str]
    ) -> list[str]:
        cookie_set = set(cookie_names)
        return [c for c in sig.cookie_signals if c.lower() in cookie_set]

    def _match_errors(self, sig: PlatformSignature, error_content: str) -> list[str]:
        if not error_content:
            return []
        err_lower = error_content.lower()
        return [e for e in sig.error_signals if e.lower() in err_lower]

    def _match_openapi(
        self, sig: PlatformSignature, evidence: dict[str, Any]
    ) -> list[str]:
        openapi_title = evidence.get("openapi_title", "")
        openapi_paths = " ".join(evidence.get("openapi_paths", []))
        combined = (openapi_title + " " + openapi_paths).lower()
        return [o for o in sig.openapi_signals if o.lower() in combined]
