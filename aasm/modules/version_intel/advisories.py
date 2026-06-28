"""
Known security advisories database for AI platforms.
Each entry maps a platform + affected version range to known vulnerabilities.
This module is intentionally additive — new advisories can be appended without
changing any other module.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SecurityAdvisory:
    """A known security advisory for a specific platform version."""
    advisory_id: str
    platform: str
    affected_versions: list[str]
    fixed_version: str | None
    severity: str
    title: str
    description: str
    cve: str | None = None
    url: str | None = None


KNOWN_ADVISORIES: list[SecurityAdvisory] = [
    SecurityAdvisory(
        advisory_id="AASM-ADV-001",
        platform="Ollama",
        affected_versions=["<0.1.34"],
        fixed_version="0.1.34",
        severity="HIGH",
        title="Ollama Remote Code Execution via Model Pull",
        description=(
            "Ollama versions prior to 0.1.34 are vulnerable to remote code execution "
            "via crafted model manifests during the pull operation (CVE-2024-37032)."
        ),
        cve="CVE-2024-37032",
        url="https://github.com/ollama/ollama/security/advisories",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-002",
        platform="Ollama",
        affected_versions=["<0.3.14"],
        fixed_version="0.3.14",
        severity="HIGH",
        title="Ollama Path Traversal Vulnerability",
        description=(
            "Ollama versions before 0.3.14 contain a path traversal vulnerability "
            "that may allow unauthorized file system access."
        ),
        cve="CVE-2024-45436",
        url="https://github.com/ollama/ollama/security/advisories",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-003",
        platform="LiteLLM",
        affected_versions=["<1.35.0"],
        fixed_version="1.35.0",
        severity="CRITICAL",
        title="LiteLLM Improper Access Control on Management API",
        description=(
            "LiteLLM versions prior to 1.35.0 allow unauthenticated access to the "
            "management API, enabling full model and key management without credentials."
        ),
        cve=None,
        url="https://github.com/BerriAI/litellm/security",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-004",
        platform="Flowise",
        affected_versions=["<2.0.0"],
        fixed_version="2.0.0",
        severity="CRITICAL",
        title="Flowise Authentication Bypass",
        description=(
            "Flowise versions prior to 2.0.0 have an authentication bypass vulnerability "
            "allowing unauthenticated access to chatflows, credentials, and API keys. "
            "(CVE-2024-31621)"
        ),
        cve="CVE-2024-31621",
        url="https://huntr.com/bounties",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-005",
        platform="Flowise",
        affected_versions=["<1.8.2"],
        fixed_version="1.8.2",
        severity="HIGH",
        title="Flowise SSRF via Chat Message",
        description=(
            "Flowise versions prior to 1.8.2 are vulnerable to Server Side Request "
            "Forgery (SSRF) via the chat message endpoint. (CVE-2024-32570)"
        ),
        cve="CVE-2024-32570",
        url="https://huntr.com/bounties",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-006",
        platform="Open WebUI",
        affected_versions=["<0.3.8"],
        fixed_version="0.3.8",
        severity="HIGH",
        title="Open WebUI XSS via Model Name",
        description=(
            "Open WebUI versions prior to 0.3.8 are vulnerable to cross-site scripting "
            "via unsanitized model names in the UI."
        ),
        cve=None,
        url="https://github.com/open-webui/open-webui/security",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-007",
        platform="vLLM",
        affected_versions=["<0.5.0"],
        fixed_version="0.5.0",
        severity="MEDIUM",
        title="vLLM Unauthenticated Metrics Exposure",
        description=(
            "vLLM versions prior to 0.5.0 expose Prometheus metrics without "
            "authentication, leaking model names, GPU usage, and request rates."
        ),
        cve=None,
        url="https://github.com/vllm-project/vllm/security",
    ),
    SecurityAdvisory(
        advisory_id="AASM-ADV-008",
        platform="AnythingLLM",
        affected_versions=["<1.0.0"],
        fixed_version="1.0.0",
        severity="HIGH",
        title="AnythingLLM Multi-User Authentication Bypass",
        description=(
            "AnythingLLM versions prior to 1.0.0 may expose workspace endpoints and "
            "documents without authentication in certain configurations."
        ),
        cve=None,
        url="https://github.com/Mintplex-Labs/anything-llm/security",
    ),
]


def get_advisories_for_platform(platform: str) -> list[SecurityAdvisory]:
    """Return all known advisories for a given platform."""
    return [a for a in KNOWN_ADVISORIES if a.platform.lower() == platform.lower()]
