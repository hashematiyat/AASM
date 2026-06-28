"""
AASM Core Data Models
Pydantic models representing all domain entities.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ServiceStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class AIServiceType(str, Enum):
    LOCAL_LLM = "local_llm"
    AI_API = "ai_api"
    AI_GATEWAY = "ai_gateway"
    AI_AGENT = "ai_agent"
    MCP_SERVER = "mcp_server"
    AI_WEB_UI = "ai_web_ui"
    VECTOR_DB = "vector_db"
    EMBEDDING_SERVICE = "embedding_service"
    UNKNOWN = "unknown"


class AuthType(str, Enum):
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC = "basic"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    UNKNOWN = "unknown"


class AIModel(BaseModel):
    id: str
    name: str
    family: str | None = None
    size: str | None = None
    quantization: str | None = None
    context_length: int | None = None
    capabilities: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class Port(BaseModel):
    number: int
    protocol: str = "tcp"
    state: ServiceStatus = ServiceStatus.UNKNOWN
    service: str | None = None
    banner: str | None = None


class AIService(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    host: str
    port: int
    url: str
    service_type: AIServiceType = AIServiceType.UNKNOWN
    platform: str | None = None
    version: str | None = None
    auth_type: AuthType = AuthType.UNKNOWN
    auth_required: bool = False
    models: list[AIModel] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    response_time_ms: float | None = None
    tls: bool = False
    open_ports: list[Port] = Field(default_factory=list)

    @property
    def display_name(self) -> str:
        return f"{self.platform or self.service_type.value} @ {self.host}:{self.port}"


class MCPTool(BaseModel):
    name: str
    description: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    dangerous: bool = False
    risk_reasons: list[str] = Field(default_factory=list)


class MCPResource(BaseModel):
    uri: str
    name: str | None = None
    mime_type: str | None = None
    description: str | None = None


class MCPPrompt(BaseModel):
    name: str
    description: str | None = None
    arguments: list[dict[str, Any]] = Field(default_factory=list)


class MCPPermission(BaseModel):
    category: str
    value: Any
    dangerous: bool = False
    description: str | None = None


class MCPServer(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    service: AIService
    server_name: str | None = None
    protocol_version: str | None = None
    tools: list[MCPTool] = Field(default_factory=list)
    resources: list[MCPResource] = Field(default_factory=list)
    prompts: list[MCPPrompt] = Field(default_factory=list)
    permissions: list[MCPPermission] = Field(default_factory=list)
    auth_required: bool = False
    auth_type: AuthType = AuthType.NONE
    dangerous_tools: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    findings: list["SecurityFinding"] = Field(default_factory=list)


class AgentCapability(str, Enum):
    WEB_BROWSING = "web_browsing"
    CODE_EXECUTION = "code_execution"
    FILE_SYSTEM = "file_system"
    DATABASE = "database"
    EMAIL = "email"
    API_CALLS = "api_calls"
    SHELL = "shell"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    MEMORY = "memory"
    MULTI_AGENT = "multi_agent"


class AIAgent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    service: AIService
    agent_name: str | None = None
    framework: str | None = None
    capabilities: list[AgentCapability] = Field(default_factory=list)
    connected_mcp_servers: list[str] = Field(default_factory=list)
    connected_apis: list[str] = Field(default_factory=list)
    tool_chain: list[str] = Field(default_factory=list)
    memory_enabled: bool = False
    persistence_enabled: bool = False
    external_integrations: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    findings: list["SecurityFinding"] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    severity: Severity
    category: str
    asset_id: UUID | None = None
    asset_url: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    cve: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class AttackPath(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    name: str
    description: str
    steps: list[str]
    severity: Severity
    assets_involved: list[UUID] = Field(default_factory=list)
    entry_point: str | None = None
    impact: str | None = None
    likelihood: float = 0.5


class RiskScore(BaseModel):
    overall: float = 0.0
    exposure: float = 0.0
    authentication: float = 0.0
    permissions: float = 0.0
    data_sensitivity: float = 0.0
    network_exposure: float = 0.0
    label: str = "UNKNOWN"

    def compute_label(self) -> str:
        if self.overall >= 9.0:
            return "CRITICAL"
        elif self.overall >= 7.0:
            return "HIGH"
        elif self.overall >= 4.0:
            return "MEDIUM"
        elif self.overall >= 1.0:
            return "LOW"
        return "INFO"


class ScanResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    target: str
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    services: list[AIService] = Field(default_factory=list)
    mcp_servers: list[MCPServer] = Field(default_factory=list)
    agents: list[AIAgent] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    risk_score: RiskScore = Field(default_factory=RiskScore)
    scan_profile: str = "default"
    modules_run: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def critical_findings(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[SecurityFinding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]
