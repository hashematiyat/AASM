"""
AASM Configuration Management
Handles YAML config files, environment variables, and scan profiles.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field


class ScanProfile(BaseModel):
    name: str
    description: str = ""
    ports: list[int] = Field(default_factory=list)
    timeout: float = 5.0
    concurrency: int = 50
    aggressive: bool = False
    include_modules: list[str] = Field(default_factory=list)


class DiscoveryConfig(BaseModel):
    timeout: float = 5.0
    concurrency: int = 50
    retries: int = 2
    user_agent: str = "AASM/0.1.0 (AI Attack Surface Mapper)"
    follow_redirects: bool = True
    verify_ssl: bool = False
    ports: list[int] = Field(default_factory=lambda: [
        11434, 3000, 1234, 4000, 7860, 8080, 8000, 8888,
        5000, 5001, 6000, 7000, 9000, 11435, 3001, 4001,
        8001, 8443, 443, 80, 9090, 7878, 3333,
    ])


class MCPConfig(BaseModel):
    timeout: float = 10.0
    enumerate_tools: bool = True
    enumerate_resources: bool = True
    enumerate_prompts: bool = True
    check_auth: bool = True


class AssessmentConfig(BaseModel):
    prompt_injection: bool = True
    prompt_leakage: bool = True
    jailbreak: bool = False
    tool_abuse: bool = True
    max_payloads: int = 20
    timeout: float = 30.0


class ReportingConfig(BaseModel):
    output_dir: str = "./aasm_reports"
    formats: list[str] = Field(default_factory=lambda: ["json", "html"])
    include_executive_summary: bool = True
    include_mitre_mapping: bool = True
    include_owasp_mapping: bool = True


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./aasm.db"
    echo: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str | None = None
    json_format: bool = False


class AASMConfig(BaseModel):
    version: str = "1"
    discovery: DiscoveryConfig = Field(default_factory=DiscoveryConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    assessment: AssessmentConfig = Field(default_factory=AssessmentConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    profiles: dict[str, ScanProfile] = Field(default_factory=dict)
    plugins: list[str] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> "AASMConfig":
        """
        Load configuration from:
        1. CLI --config path
        2. AASM_CONFIG environment variable
        3. ~/.config/aasm/config.yaml
        4. /etc/aasm/config.yaml
        5. ./aasm.yaml

        If none exist, return the default configuration.
        """

        env_config = os.environ.get("AASM_CONFIG")

        search_paths: list[Path | None] = [
            path,
            Path(env_config) if env_config else None,
            Path.home() / ".config" / "aasm" / "config.yaml",
            Path("/etc/aasm/config.yaml"),
            Path("aasm.yaml"),
        ]

        for p in search_paths:
            if p is None:
                continue

            if not p.exists():
                continue

            if not p.is_file():
                continue

            try:
                with p.open("r", encoding="utf-8") as f:
                    data: dict[str, Any] = yaml.safe_load(f) or {}

                return cls.model_validate(data)

            except Exception as e:
                raise RuntimeError(
                    f"Failed to load configuration file '{p}': {e}"
                ) from e

        return cls()

    def get_profile(self, name: str) -> ScanProfile | None:
        return self.profiles.get(name)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)

        with path.open("w", encoding="utf-8") as f:
            yaml.dump(
                self.model_dump(),
                f,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )


_config: AASMConfig | None = None


def get_config(path: Path | None = None) -> AASMConfig:
    global _config

    if _config is None:
        _config = AASMConfig.load(path)

    return _config


def reset_config() -> None:
    global _config
    _config = None
