"""
Module 8 — Reporting Engine
Generates professional enterprise security reports in multiple formats.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from aasm.core.logger import get_logger
from aasm.core.models import ScanResult, Severity

logger = get_logger("reporting")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AASM Security Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f1117; color: #e1e4e8; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #1a1f2e, #0d1117);
             border-bottom: 2px solid #ff6b35; padding: 40px; }}
  .header h1 {{ font-size: 2rem; font-weight: 700; color: #ff6b35; }}
  .header .subtitle {{ color: #8b949e; margin-top: 8px; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
  .risk-banner {{ background: {risk_bg}; border-radius: 12px; padding: 24px;
                  margin-bottom: 32px; display: flex; align-items: center; gap: 20px; }}
  .risk-score {{ font-size: 4rem; font-weight: 900; color: {risk_color}; }}
  .risk-label {{ font-size: 1.5rem; font-weight: 700; color: {risk_color}; }}
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px;
              padding: 24px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 1.2rem; font-weight: 700; color: #58a6ff;
                 border-bottom: 1px solid #30363d; padding-bottom: 12px; margin-bottom: 16px; }}
  .finding {{ border-left: 4px solid {severity_color}; padding: 16px; margin-bottom: 12px;
              background: #0d1117; border-radius: 0 8px 8px 0; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px;
            font-size: 0.75rem; font-weight: 700; }}
  .badge-critical {{ background: #ff000033; color: #ff4444; }}
  .badge-high {{ background: #ff6b3533; color: #ff6b35; }}
  .badge-medium {{ background: #f0ad4e33; color: #f0ad4e; }}
  .badge-low {{ background: #28a74533; color: #28a745; }}
  .badge-info {{ background: #17a2b833; color: #17a2b8; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #21262d; padding: 12px; text-align: left; color: #8b949e;
       font-size: 0.8rem; text-transform: uppercase; }}
  td {{ padding: 12px; border-bottom: 1px solid #21262d; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
               gap: 16px; }}
  .stat {{ background: #21262d; border-radius: 8px; padding: 16px; text-align: center; }}
  .stat-value {{ font-size: 2rem; font-weight: 900; color: #58a6ff; }}
  .stat-label {{ font-size: 0.8rem; color: #8b949e; margin-top: 4px; }}
  .attack-path {{ background: #0d1117; border: 1px solid #ff6b35; border-radius: 8px;
                  padding: 16px; margin-bottom: 12px; }}
  .attack-path ol {{ padding-left: 20px; margin-top: 8px; }}
  .attack-path li {{ padding: 4px 0; color: #8b949e; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace;
          font-size: 0.85rem; color: #79c0ff; }}
  .footer {{ text-align: center; padding: 40px; color: #8b949e; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>AI Attack Surface Mapper</h1>
  <div class="subtitle">Enterprise AI Security Assessment Report</div>
  <div class="subtitle">Target: <code>{target}</code> &nbsp;|&nbsp; Generated: {generated_at}</div>
</div>
<div class="container">

  <div class="risk-banner">
    <div class="risk-score">{overall_score}</div>
    <div>
      <div class="risk-label">{risk_label} RISK</div>
      <div style="color:#8b949e; margin-top:4px">Overall AI Attack Surface Risk Score (out of 10.0)</div>
    </div>
  </div>

  <div class="section">
    <h2>Attack Surface Overview</h2>
    <div class="stat-grid">
      <div class="stat"><div class="stat-value">{svc_count}</div><div class="stat-label">AI Services</div></div>
      <div class="stat"><div class="stat-value">{mcp_count}</div><div class="stat-label">MCP Servers</div></div>
      <div class="stat"><div class="stat-value">{agent_count}</div><div class="stat-label">AI Agents</div></div>
      <div class="stat"><div class="stat-value">{finding_count}</div><div class="stat-label">Findings</div></div>
      <div class="stat"><div class="stat-value" style="color:#ff4444">{critical_count}</div><div class="stat-label">Critical</div></div>
      <div class="stat"><div class="stat-value" style="color:#ff6b35">{high_count}</div><div class="stat-label">High</div></div>
      <div class="stat"><div class="stat-value">{path_count}</div><div class="stat-label">Attack Paths</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Security Findings</h2>
    {findings_html}
  </div>

  <div class="section">
    <h2>AI Asset Inventory</h2>
    <table>
      <thead><tr><th>Platform</th><th>Host:Port</th><th>Type</th><th>Auth</th><th>Models</th></tr></thead>
      <tbody>{assets_html}</tbody>
    </table>
  </div>

  {attack_paths_html}

  <div class="section">
    <h2>Risk Score Breakdown</h2>
    <table>
      <thead><tr><th>Category</th><th>Score</th></tr></thead>
      <tbody>
        <tr><td>Exposure</td><td><code>{exposure}/10</code></td></tr>
        <tr><td>Authentication</td><td><code>{auth}/10</code></td></tr>
        <tr><td>Permissions</td><td><code>{perms}/10</code></td></tr>
        <tr><td>Network Exposure</td><td><code>{network}/10</code></td></tr>
        <tr><td>Data Sensitivity</td><td><code>{data}/10</code></td></tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>OWASP LLM Top 10 2025 Coverage</h2>
    <table>
      <thead><tr><th>ID</th><th>Category</th><th>Findings</th></tr></thead>
      <tbody>{owasp_html}</tbody>
    </table>
  </div>

</div>
<div class="footer">Generated by AASM v0.1.0 — AI Attack Surface Mapper | {generated_at}</div>
</body>
</html>
"""

RISK_COLORS = {
    "CRITICAL": ("#ff000015", "#ff4444"),
    "HIGH": ("#ff6b3515", "#ff6b35"),
    "MEDIUM": ("#f0ad4e15", "#f0ad4e"),
    "LOW": ("#28a74515", "#28a745"),
    "INFO": ("#17a2b815", "#17a2b8"),
    "UNKNOWN": ("#30363d", "#8b949e"),
}

SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff6b35",
    "MEDIUM": "#f0ad4e",
    "LOW": "#28a745",
    "INFO": "#17a2b8",
}

OWASP_LLM_CATEGORIES = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM03", "Supply Chain"),
    ("LLM04", "Data and Model Poisoning"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM08", "Vector and Embedding Weaknesses"),
    ("LLM09", "Misinformation"),
    ("LLM10", "Unbounded Consumption"),
]


class ReportingEngine:
    """Generates HTML, JSON, and SARIF security reports."""

    def __init__(self, output_dir: str = "./aasm_reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        result: ScanResult,
        formats: list[str] | None = None,
    ) -> dict[str, Path]:
        formats = formats or ["json", "html"]
        outputs: dict[str, Path] = {}
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        stem = f"aasm_report_{result.target.replace('/', '_')}_{timestamp}"

        if "json" in formats:
            path = self.output_dir / f"{stem}.json"
            self._write_json(result, path)
            outputs["json"] = path

        if "html" in formats:
            path = self.output_dir / f"{stem}.html"
            self._write_html(result, path)
            outputs["html"] = path

        if "sarif" in formats:
            path = self.output_dir / f"{stem}.sarif"
            self._write_sarif(result, path)
            outputs["sarif"] = path

        logger.info(f"Reports written to {self.output_dir}")
        return outputs

    def _write_json(self, result: ScanResult, path: Path) -> None:
        data = result.model_dump(mode="json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def _write_html(self, result: ScanResult, path: Path) -> None:
        risk_label = result.risk_score.label
        risk_bg, risk_color = RISK_COLORS.get(risk_label, RISK_COLORS["UNKNOWN"])

        all_findings = result.findings.copy()
        for mcp in result.mcp_servers:
            all_findings.extend(mcp.findings)
        for agent in result.agents:
            all_findings.extend(agent.findings)

        all_findings.sort(
            key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(f.severity.value)
        )

        findings_html = ""
        for f in all_findings[:50]:
            badge_cls = f"badge-{f.severity.value.lower()}"
            sev_color = SEVERITY_COLORS.get(f.severity.value, "#8b949e")
            rem = f"<p style='margin-top:8px;color:#8b949e;font-size:0.9rem'>Remediation: {f.remediation}</p>" if f.remediation else ""
            owasp = ", ".join(f"<code>{o}</code>" for o in f.owasp_categories) if f.owasp_categories else ""
            mitre = ", ".join(f"<code>{m}</code>" for m in f.mitre_techniques) if f.mitre_techniques else ""
            findings_html += f"""
            <div class="finding" style="border-left-color:{sev_color}">
              <span class="badge {badge_cls}">{f.severity.value}</span>
              <strong style="margin-left:8px">{f.title}</strong>
              <p style="margin-top:8px;color:#8b949e">{f.description}</p>
              {rem}
              {"<p style='margin-top:6px;font-size:0.8rem'>OWASP: " + owasp + "</p>" if owasp else ""}
              {"<p style='margin-top:4px;font-size:0.8rem'>MITRE: " + mitre + "</p>" if mitre else ""}
            </div>"""

        assets_html = ""
        for svc in result.services:
            auth_badge = f'<span class="badge badge-{"info" if svc.auth_required else "critical"}">{"Auth" if svc.auth_required else "No Auth"}</span>'
            model_names = ", ".join(m.name for m in svc.models[:3])
            if len(svc.models) > 3:
                model_names += f" +{len(svc.models) - 3} more"
            assets_html += f"<tr><td><code>{svc.platform or 'Unknown'}</code></td><td><code>{svc.host}:{svc.port}</code></td><td>{svc.service_type.value}</td><td>{auth_badge}</td><td>{model_names or '—'}</td></tr>"

        attack_paths_html = ""
        if result.attack_paths:
            paths_content = ""
            for ap in result.attack_paths:
                sev_color = SEVERITY_COLORS.get(ap.severity.value, "#8b949e")
                steps_html = "".join(f"<li>{s}</li>" for s in ap.steps)
                paths_content += f"""
                <div class="attack-path">
                  <div style="display:flex;justify-content:space-between;align-items:center">
                    <strong>{ap.name}</strong>
                    <span class="badge badge-{ap.severity.value.lower()}">{ap.severity.value}</span>
                  </div>
                  <p style="color:#8b949e;margin-top:8px">{ap.description}</p>
                  <ol style="margin-top:12px">{steps_html}</ol>
                  {"<p style='margin-top:8px;font-size:0.85rem;color:#ff6b35'>Impact: " + ap.impact + "</p>" if ap.impact else ""}
                </div>"""
            attack_paths_html = f'<div class="section"><h2>Attack Paths</h2>{paths_content}</div>'

        owasp_finding_map: dict[str, int] = {}
        for f in all_findings:
            for cat in f.owasp_categories:
                for owasp_id, _ in OWASP_LLM_CATEGORIES:
                    if owasp_id in cat:
                        owasp_finding_map[owasp_id] = owasp_finding_map.get(owasp_id, 0) + 1

        owasp_html = ""
        for owasp_id, owasp_name in OWASP_LLM_CATEGORIES:
            count = owasp_finding_map.get(owasp_id, 0)
            badge = f'<span class="badge badge-critical">{count}</span>' if count > 0 else "—"
            owasp_html += f"<tr><td><code>{owasp_id}</code></td><td>{owasp_name}</td><td>{badge}</td></tr>"

        critical_count = len([f for f in all_findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in all_findings if f.severity == Severity.HIGH])

        html = HTML_TEMPLATE.format(
            target=result.target,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            risk_bg=risk_bg,
            risk_color=risk_color,
            risk_label=risk_label,
            overall_score=f"{result.risk_score.overall:.1f}",
            svc_count=len(result.services),
            mcp_count=len(result.mcp_servers),
            agent_count=len(result.agents),
            finding_count=len(all_findings),
            critical_count=critical_count,
            high_count=high_count,
            path_count=len(result.attack_paths),
            findings_html=findings_html,
            assets_html=assets_html,
            attack_paths_html=attack_paths_html,
            owasp_html=owasp_html,
            severity_color="#ff4444",
            exposure=result.risk_score.exposure,
            auth=result.risk_score.authentication,
            perms=result.risk_score.permissions,
            network=result.risk_score.network_exposure,
            data=result.risk_score.data_sensitivity,
        )
        with open(path, "w") as f:
            f.write(html)

    def _write_sarif(self, result: ScanResult, path: Path) -> None:
        sarif: dict[str, Any] = {
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AASM",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/aasm-project/aasm",
                        "rules": [],
                    }
                },
                "results": [],
            }]
        }
        all_findings = result.findings.copy()
        for mcp in result.mcp_servers:
            all_findings.extend(mcp.findings)
        for agent in result.agents:
            all_findings.extend(agent.findings)

        level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }

        rules = []
        rule_ids: set[str] = set()
        sarif_results = []

        for f in all_findings:
            rule_id = f.category.replace(" ", "_").upper()
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": f.title},
                    "helpUri": "https://aasm.dev/rules",
                })
            sarif_results.append({
                "ruleId": rule_id,
                "level": level_map.get(f.severity.value, "warning"),
                "message": {"text": f.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.asset_url or result.target}
                    }
                }],
            })

        sarif["runs"][0]["tool"]["driver"]["rules"] = rules  # type: ignore[index]
        sarif["runs"][0]["results"] = sarif_results  # type: ignore[index]

        with open(path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)
