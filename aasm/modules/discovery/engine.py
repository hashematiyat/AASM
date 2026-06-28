"""
Module 1 — AI Discovery Engine
Scans networks and detects AI services across enterprise environments.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import AsyncGenerator

import httpx
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn, BarColumn, TimeElapsedColumn

from aasm.core.config import DiscoveryConfig
from aasm.core.logger import get_logger
from aasm.core.models import AIService

from .platforms import ALL_DETECTORS, BasePlatformDetector

logger = get_logger("discovery")


def expand_target(target: str) -> list[str]:
    """Expand CIDR, range, or single IP/hostname to list of hosts."""
    hosts: list[str] = []
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
        if not hosts:
            hosts = [str(network.network_address)]
        return hosts
    except ValueError:
        pass
    if "-" in target.split(".")[-1]:
        parts = target.split(".")
        base = ".".join(parts[:3])
        range_part = parts[3]
        start, end = range_part.split("-")
        return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]
    return [target]


class DiscoveryEngine:
    """
    Scans networks for AI services using async HTTP probing.
    Supports CIDR ranges, individual hosts, port lists, and scan profiles.
    """

    def __init__(self, config: DiscoveryConfig | None = None) -> None:
        self.config = config or DiscoveryConfig()
        self._semaphore = asyncio.Semaphore(self.config.concurrency)
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "DiscoveryEngine":
        self._client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            follow_redirects=self.config.follow_redirects,
            timeout=self.config.timeout,
            headers={"User-Agent": self.config.user_agent},
        )
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    def _get_detectors(self) -> list[BasePlatformDetector]:
        assert self._client is not None
        return [cls(self._client) for cls in ALL_DETECTORS]

    async def scan_host_port(self, host: str, port: int) -> AIService | None:
        """Probe a single host:port with all detectors."""
        async with self._semaphore:
            detectors = self._get_detectors()
            for detector in detectors:
                if port not in detector.default_ports and port not in self.config.ports:
                    continue
                try:
                    t0 = time.monotonic()
                    service = await detector.detect(host, port)
                    if service:
                        service.response_time_ms = (time.monotonic() - t0) * 1000
                        logger.info(
                            f"[+] Found {service.platform} at {host}:{port}"
                        )
                        return service
                except Exception as e:
                    logger.debug(f"Detector {detector.platform_name} error at {host}:{port}: {e}")
            return None

    async def scan_host(self, host: str, ports: list[int] | None = None) -> list[AIService]:
        """Scan all ports on a single host."""
        target_ports = ports or self.config.ports
        tasks = [self.scan_host_port(host, port) for port in target_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        services: list[AIService] = []
        for r in results:
            if isinstance(r, AIService):
                services.append(r)
        return services

    async def scan(
        self,
        target: str,
        ports: list[int] | None = None,
        progress: Progress | None = None,
        task_id: TaskID | None = None,
    ) -> list[AIService]:
        """
        Scan a target (CIDR, range, or hostname) for AI services.
        Returns all discovered services.
        """
        hosts = expand_target(target)
        all_services: list[AIService] = []
        total = len(hosts)

        logger.info(f"Scanning {total} hosts on target {target}")

        for i, host in enumerate(hosts):
            services = await self.scan_host(host, ports)
            all_services.extend(services)
            if progress and task_id is not None:
                progress.update(task_id, advance=1,
                                description=f"[cyan]Scanning {host}...")

        return all_services

    async def scan_stream(
        self,
        target: str,
        ports: list[int] | None = None,
    ) -> AsyncGenerator[AIService, None]:
        """Stream discovered services as they are found."""
        hosts = expand_target(target)
        target_ports = ports or self.config.ports

        async def probe_and_yield(host: str, port: int) -> list[AIService]:
            result = await self.scan_host_port(host, port)
            return [result] if result else []

        tasks = [
            probe_and_yield(host, port)
            for host in hosts
            for port in target_ports
        ]

        for coro in asyncio.as_completed(tasks):
            results = await coro
            for svc in results:
                yield svc
