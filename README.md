# AASM — AI Attack Surface Mapper

[![CI](https://github.com/aasm-project/aasm/actions/workflows/ci.yml/badge.svg)](https://github.com/aasm-project/aasm/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Enterprise CLI for discovering, fingerprinting, and securing AI infrastructure.

AASM is a professional Linux CLI cybersecurity platform built for **penetration testers, AI security engineers, blue teams, and red teams**. It discovers and assesses AI ecosystems including Local LLMs, MCP Servers, AI Agents, AI Gateways, and AI APIs.

Designed in the philosophy of **Nmap, BloodHound, and Trivy** — but specialized for AI infrastructure.

---

## Quick Start

```bash
# Install from PyPI
pip install aasm

# Or install from source
git clone https://github.com/aasm-project/aasm
cd aasm
pip install -e .

# Run a scan
aasm scan 192.168.1.0/24

# Discover AI services on localhost
aasm discover localhost

# Audit a specific service
aasm audit http://localhost:11434

# Discover MCP servers
aasm mcp 192.168.1.0/24
```

---

## Features

| Module | Capability |
|--------|-----------|
| **Discovery** | Scans networks for Ollama, Open WebUI, LM Studio, LiteLLM, vLLM, HuggingFace TGI, Flowise, and more |
| **Fingerprinting** | Deep service fingerprinting — version, models, endpoints, auth, framework |
| **MCP Scanner** | JSON-RPC 2.0 MCP server discovery with tool/resource/prompt enumeration |
| **MCP Analyzer** | Security analysis of MCP permissions, dangerous tools, and trust boundaries |
| **Agent Analyzer** | Discovers AI agent frameworks and maps capabilities and risk |
| **Assessment** | Prompt injection, system prompt disclosure, jailbreak, auth bypass testing |
| **Attack Surface Mapper** | Builds asset inventory and discovers multi-hop attack paths |
| **Risk Engine** | CVSS-style scoring with MITRE ATT&CK and OWASP LLM Top 10 mapping |
| **Reporting** | HTML, JSON, and SARIF report generation |
| **Visualization** | Graphviz DOT and Mermaid attack surface diagrams |

---

## CLI Commands

```
aasm scan 192.168.1.0/24                  # Full AI infrastructure scan
aasm discover 10.0.0.0/24                 # Quick service discovery
aasm fingerprint http://localhost:11434    # Deep fingerprint one service
aasm audit http://localhost:3000          # Security audit a service
aasm mcp 192.168.1.0/24                  # Discover & audit MCP servers
aasm agents 10.0.0.0/24                  # Discover AI agents
aasm assess http://localhost:11434        # Offensive security assessment
aasm graph scan_result.json              # Generate infrastructure graph
aasm report scan_result.json             # Generate HTML/SARIF reports
aasm risk scan_result.json               # Risk scoring & executive summary
aasm platforms                            # List supported AI platforms
aasm version                              # Show version
```

### Global Options

```
--config / -c      Config file path (default: aasm.yaml or ~/.config/aasm/config.yaml)
--verbose / -v     Verbose output
--debug            Debug mode
```

### Scan Options

```bash
aasm scan 192.168.1.0/24 \
  --ports 11434,3000,8080 \
  --profile aggressive \
  --formats json,html,sarif \
  --output ./reports \
  --no-fingerprint \
  --no-mcp \
  --no-risk
```

---

## Supported AI Platforms

| Platform | Type | Default Ports |
|----------|------|---------------|
| Ollama | Local LLM | 11434, 11435 |
| Open WebUI | AI Web UI | 3000, 8080 |
| LM Studio | Local LLM | 1234, 1235 |
| LiteLLM | AI Gateway | 4000, 8000 |
| vLLM | Local LLM | 8000, 8080 |
| HuggingFace TGI | Local LLM | 8080, 3000 |
| Flowise | AI Agent | 3000, 3001 |
| OpenAI-Compatible APIs | AI API | 8000, 5000, … |

The plugin system allows adding new platforms without modifying core code.

---

## Docker

```bash
# Build
docker build -t aasm .

# Scan a network
docker run --rm -it --network host aasm scan 192.168.1.0/24

# Save reports to host
docker run --rm -it \
  --network host \
  -v $(pwd)/reports:/home/aasm/aasm_reports \
  aasm scan 192.168.1.0/24 -o /home/aasm/aasm_reports
```

---

## Configuration

```bash
# Generate a default config
aasm config --init

# Show effective config
aasm config --show
```

`aasm.yaml`:
```yaml
version: "1"

discovery:
  timeout: 5.0
  concurrency: 50
  verify_ssl: false
  ports: [11434, 3000, 1234, 4000, 8080, 8000]

assessment:
  prompt_injection: true
  prompt_leakage: true
  jailbreak: false
  max_payloads: 20

reporting:
  output_dir: ./aasm_reports
  formats: [json, html]

profiles:
  quick:
    name: quick
    ports: [11434, 3000, 1234, 4000]
    timeout: 3.0
    concurrency: 100
```

Use profiles: `aasm scan 192.168.1.0/24 --profile aggressive`

---

## Plugin System

Add new platform detectors or assessment modules without touching core code:

```python
# my_plugin.py
from aasm.plugins.base import DetectorPlugin
from aasm.core.models import AIService, AIServiceType

class MyCustomDetector(DetectorPlugin):
    name = "my-platform"
    version = "1.0.0"
    description = "Detects MyCustom AI platform"
    platform_name = "MyCustom"
    default_ports = [9999]

    async def detect(self, host: str, port: int) -> AIService | None:
        # Your detection logic here
        ...
```

Load plugins:
```bash
aasm plugins --load ./my_plugins/
```

---

## Report Formats

| Format | Description |
|--------|-------------|
| **JSON** | Machine-readable full scan result (suitable for SIEM ingestion) |
| **HTML** | Professional dark-themed HTML report with risk matrix |
| **SARIF** | Static Analysis Results Interchange Format (GitHub, Azure DevOps) |

---

## Security Assessments

> ⚠ Only assess systems you own or have explicit written permission to test.

```bash
# Standard assessment (prompt injection + auth bypass)
aasm assess http://localhost:11434

# Full offensive assessment (includes jailbreak testing)
aasm assess http://localhost:11434 --jailbreak

# Targeted test
aasm assess http://localhost:11434 --no-prompt-injection --auth-bypass
```

OWASP LLM Top 10 2025 coverage:
- LLM01 — Prompt Injection
- LLM02 — Sensitive Information Disclosure
- LLM06 — Excessive Agency
- LLM07 — System Prompt Leakage
- LLM08 — Weak Guardrails

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=aasm

# Lint
ruff check aasm/

# Type check
mypy aasm/
```

---

## Architecture

```
aasm/
├── aasm/
│   ├── cli/                    # Typer CLI commands
│   │   ├── main.py             # App entry point
│   │   ├── output.py           # Rich terminal output
│   │   └── commands/           # One file per subcommand
│   ├── core/                   # Shared domain
│   │   ├── config.py           # YAML config & profiles
│   │   ├── logger.py           # Enterprise logging
│   │   └── models.py           # Pydantic domain models
│   ├── modules/                # Feature modules (9 modules)
│   │   ├── discovery/          # Module 1 — AI Discovery Engine
│   │   │   └── platforms/      # Per-platform detectors (plugin-able)
│   │   ├── fingerprint/        # Module 2 — Fingerprinting Engine
│   │   ├── mcp/                # Module 3 — MCP Scanner & Analyzer
│   │   ├── agents/             # Module 4 — AI Agent Analyzer
│   │   ├── assessment/         # Module 5 — Security Assessment Engine
│   │   ├── mapper/             # Module 6 — Attack Surface Mapper
│   │   ├── risk/               # Module 7 — Risk Engine
│   │   ├── reporting/          # Module 8 — Reporting Engine
│   │   └── visualization/      # Module 9 — Visualization Engine
│   └── plugins/                # Plugin framework
├── tests/                      # pytest test suite
├── config/                     # Default YAML configs
├── Dockerfile
├── pyproject.toml
└── README.md
```

---

## MITRE ATT&CK & OWASP Mapping

AASM maps all findings to:
- **MITRE ATT&CK** (T-codes for traditional TTPs)
- **MITRE ATLAS** (AML-codes for AI/ML specific threats)
- **OWASP LLM Top 10 2025** for AI-specific vulnerability categories

---

## Roadmap

- [ ] PDF report generation
- [ ] Neo4j graph export for BloodHound-style visualization
- [ ] MITRE ATLAS full mapping
- [ ] Kubernetes AI workload discovery
- [ ] Real-time streaming scan output
- [ ] CI/CD pipeline integration mode
- [ ] Langchain/LangGraph agent detection
- [ ] OpenTelemetry tracing
- [ ] Web dashboard (optional companion)

---

## License

MIT — See [LICENSE](LICENSE)

---

*AASM is intended for authorized security testing only. Always obtain written permission before scanning networks or systems you do not own.*
