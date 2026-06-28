"""Tests for the risk engine."""

import pytest
from aasm.core.models import AIService, AIServiceType, ScanResult, SecurityFinding, Severity
from aasm.modules.risk.engine import RiskEngine


def _make_service(auth_required: bool = False, host: str = "192.168.1.1") -> AIService:
    return AIService(
        host=host,
        port=11434,
        url=f"http://{host}:11434",
        service_type=AIServiceType.LOCAL_LLM,
        platform="Ollama",
        auth_required=auth_required,
    )


def test_risk_score_zero_no_findings():
    engine = RiskEngine()
    result = ScanResult(target="192.168.1.1")
    result = engine.calculate(result)
    assert result.risk_score.overall == 0.0


def test_unauthenticated_services_raise_score():
    engine = RiskEngine()
    result = ScanResult(target="192.168.1.0/24")
    result.services = [_make_service(auth_required=False) for _ in range(5)]
    result = engine.calculate(result)
    assert result.risk_score.overall > 0.0


def test_authenticated_services_lower_auth_score():
    engine = RiskEngine()
    result_no_auth = ScanResult(target="test")
    result_no_auth.services = [_make_service(auth_required=False)]

    result_auth = ScanResult(target="test")
    result_auth.services = [_make_service(auth_required=True)]

    engine.calculate(result_no_auth)
    engine.calculate(result_auth)

    assert result_no_auth.risk_score.authentication >= result_auth.risk_score.authentication


def test_executive_summary_generated():
    engine = RiskEngine()
    result = ScanResult(target="10.0.0.0/24")
    result.services = [_make_service()]
    result.findings = [
        SecurityFinding(
            title="Test Critical",
            description="A critical finding",
            severity=Severity.CRITICAL,
            category="Test",
        )
    ]
    result = engine.calculate(result)
    summary = engine.generate_executive_summary(result)
    assert "Risk Score" in summary
    assert "10.0.0.0/24" in summary or "services" in summary.lower()


def test_findings_enriched_with_mitre():
    engine = RiskEngine()
    result = ScanResult(target="test")
    result.findings = [
        SecurityFinding(
            title="Prompt Injection",
            description="Test",
            severity=Severity.CRITICAL,
            category="Prompt Injection",
        )
    ]
    result = engine.calculate(result)
    assert any(len(f.mitre_techniques) > 0 for f in result.findings)
