"""Tests for AASM core data models."""

import pytest
from uuid import UUID
from aasm.core.models import (
    AIService,
    AIServiceType,
    AuthType,
    MCPServer,
    MCPTool,
    RiskScore,
    ScanResult,
    SecurityFinding,
    Severity,
)


def test_ai_service_creation():
    svc = AIService(
        host="192.168.1.10",
        port=11434,
        url="http://192.168.1.10:11434",
        service_type=AIServiceType.LOCAL_LLM,
        platform="Ollama",
    )
    assert svc.host == "192.168.1.10"
    assert svc.port == 11434
    assert svc.platform == "Ollama"
    assert isinstance(svc.id, UUID)


def test_ai_service_display_name():
    svc = AIService(
        host="localhost",
        port=11434,
        url="http://localhost:11434",
        service_type=AIServiceType.LOCAL_LLM,
        platform="Ollama",
    )
    assert "Ollama" in svc.display_name
    assert "localhost" in svc.display_name


def test_risk_score_label_critical():
    score = RiskScore(overall=9.5)
    assert score.compute_label() == "CRITICAL"


def test_risk_score_label_high():
    score = RiskScore(overall=7.5)
    assert score.compute_label() == "HIGH"


def test_risk_score_label_medium():
    score = RiskScore(overall=5.0)
    assert score.compute_label() == "MEDIUM"


def test_risk_score_label_low():
    score = RiskScore(overall=2.0)
    assert score.compute_label() == "LOW"


def test_scan_result_critical_findings():
    svc = AIService(
        host="test", port=80, url="http://test",
        service_type=AIServiceType.UNKNOWN,
    )
    finding_crit = SecurityFinding(
        title="Critical Issue",
        description="A critical vulnerability",
        severity=Severity.CRITICAL,
        category="Test",
    )
    finding_high = SecurityFinding(
        title="High Issue",
        description="A high vulnerability",
        severity=Severity.HIGH,
        category="Test",
    )
    result = ScanResult(target="192.168.1.0/24")
    result.findings = [finding_crit, finding_high]
    assert len(result.critical_findings) == 1
    assert len(result.high_findings) == 1


def test_mcp_tool_dangerous():
    tool = MCPTool(
        name="bash_execute",
        description="Execute bash commands",
        dangerous=True,
        risk_reasons=["Shell command execution"],
    )
    assert tool.dangerous
    assert "Shell command execution" in tool.risk_reasons


def test_scan_result_duration():
    from datetime import datetime, timedelta
    result = ScanResult(target="10.0.0.1")
    result.completed_at = result.started_at + timedelta(seconds=42)
    assert result.duration_seconds == pytest.approx(42.0, abs=0.1)
