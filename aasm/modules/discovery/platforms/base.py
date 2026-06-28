"""
Base class for all platform detectors.
Each detector handles fingerprinting a specific AI platform or service type.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import httpx

from aasm.core.models import AIService, AIServiceType, AuthType


class BasePlatformDetector(ABC):
    platform_name: str = "unknown"
    service_type: AIServiceType = AIServiceType.UNKNOWN
    default_ports: list[int] = []
    probe_paths: list[str] = []

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    @abstractmethod
    async def detect(self, host: str, port: int) -> AIService | None:
        """Try to detect this platform at host:port. Return AIService if found."""
        ...

    async def _probe(self, url: str) -> httpx.Response | None:
        try:
            r = await self.client.get(url, timeout=5.0)
            return r
        except Exception:
            return None

    async def _probe_json(self, url: str) -> dict[str, Any] | None:
        r = await self._probe(url)
        if r is not None and r.status_code < 500:
            try:
                return r.json()
            except Exception:
                pass
        return None

    def _build_url(self, host: str, port: int, path: str = "") -> str:
        scheme = "https" if port in (443, 8443) else "http"
        return f"{scheme}://{host}:{port}{path}"

    def _detect_auth(self, response: httpx.Response) -> tuple[bool, AuthType]:
        if response.status_code == 401:
            auth_header = response.headers.get("WWW-Authenticate", "").lower()
            if "bearer" in auth_header:
                return True, AuthType.BEARER_TOKEN
            if "basic" in auth_header:
                return True, AuthType.BASIC
            return True, AuthType.UNKNOWN
        if response.status_code == 403:
            return True, AuthType.UNKNOWN
        return False, AuthType.NONE
