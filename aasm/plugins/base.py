"""
AASM Plugin System
Extensible plugin framework for adding new platform detectors,
assessment modules, and reporting backends.
"""

from __future__ import annotations

import importlib
import importlib.util
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from aasm.core.logger import get_logger

if TYPE_CHECKING:
    from aasm.core.models import AIService, SecurityFinding

logger = get_logger("plugins")


class BasePlugin(ABC):
    """Base class for all AASM plugins."""

    name: str = "unnamed"
    version: str = "0.0.0"
    description: str = ""
    author: str = ""

    @abstractmethod
    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        """Execute the plugin. Returns a dict of results."""
        ...

    def setup(self, config: dict[str, Any]) -> None:
        """Optional setup hook called before run()."""
        pass

    def teardown(self) -> None:
        """Optional teardown hook called after run()."""
        pass


class DetectorPlugin(BasePlugin):
    """Plugin base class for adding new AI platform detectors."""

    platform_name: str = "custom"
    default_ports: list[int] = []

    @abstractmethod
    async def detect(self, host: str, port: int) -> "AIService | None":
        """Detect platform at host:port. Return AIService if found."""
        ...

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        host = context.get("host", "")
        port = context.get("port", 80)
        service = await self.detect(host, port)
        return {"service": service}


class AssessmentPlugin(BasePlugin):
    """Plugin base class for adding new security assessment modules."""

    @abstractmethod
    async def assess(self, service: "AIService") -> list["SecurityFinding"]:
        """Run assessment against a service. Return findings."""
        ...

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        service = context.get("service")
        if not service:
            return {"findings": []}
        findings = await self.assess(service)
        return {"findings": findings}


class PluginRegistry:
    """Manages plugin loading, registration, and lifecycle."""

    def __init__(self) -> None:
        self._plugins: dict[str, BasePlugin] = {}

    def register(self, plugin: BasePlugin) -> None:
        self._plugins[plugin.name] = plugin
        logger.info(f"Plugin registered: {plugin.name} v{plugin.version}")

    def get(self, name: str) -> BasePlugin | None:
        return self._plugins.get(name)

    def list_plugins(self) -> list[dict[str, str]]:
        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "author": p.author,
                "type": type(p).__bases__[0].__name__,
            }
            for p in self._plugins.values()
        ]

    def load_from_path(self, path: Path) -> int:
        """Load plugins from a directory or Python file."""
        loaded = 0
        paths = [path] if path.is_file() else list(path.glob("*.py"))
        for plugin_path in paths:
            if plugin_path.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    plugin_path.stem, plugin_path
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)  # type: ignore[union-attr]
                    for attr_name in dir(module):
                        obj = getattr(module, attr_name)
                        if (
                            isinstance(obj, type)
                            and issubclass(obj, BasePlugin)
                            and obj not in (BasePlugin, DetectorPlugin, AssessmentPlugin)
                        ):
                            instance = obj()
                            self.register(instance)
                            loaded += 1
            except Exception as e:
                logger.warning(f"Failed to load plugin from {plugin_path}: {e}")
        return loaded

    def load_from_module(self, module_name: str) -> int:
        """Load plugins from an installed Python module."""
        loaded = 0
        try:
            module = importlib.import_module(module_name)
            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BasePlugin)
                    and obj not in (BasePlugin, DetectorPlugin, AssessmentPlugin)
                ):
                    instance = obj()
                    self.register(instance)
                    loaded += 1
        except Exception as e:
            logger.warning(f"Failed to load module {module_name}: {e}")
        return loaded


_registry = PluginRegistry()


def get_registry() -> PluginRegistry:
    return _registry
