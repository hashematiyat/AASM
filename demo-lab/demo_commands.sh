#!/usr/bin/env bash
# ============================================================
#  AASM Demo Lab — Example Commands
#  Run these AFTER starting: python lab_server.py
# ============================================================

set -e
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
  echo ""
  echo -e "${RED}╔══════════════════════════════════════════════╗${RESET}"
  echo -e "${RED}║  $1${RESET}"
  echo -e "${RED}╚══════════════════════════════════════════════╝${RESET}"
  echo ""
}

pause() {
  echo -e "\n${YELLOW}  ▶ Press Enter to run next demo...${RESET}"
  read -r
}

# ─────────────────────────────────────
banner "DEMO 1 — Full Network Scan"
echo -e "${CYAN}Command:${RESET} aasm scan 127.0.0.1 --ports 11434,3000,4000,3001,3002,8080"
pause
aasm scan 127.0.0.1 \
  --ports 11434,3000,4000,3001,3002,8080 \
  --output ./demo_reports \
  --formats json,html

# ─────────────────────────────────────
banner "DEMO 2 — Quick Discovery"
echo -e "${CYAN}Command:${RESET} aasm discover 127.0.0.1"
pause
aasm discover 127.0.0.1 \
  --ports 11434,3000,4000,3001,3002,8080

# ─────────────────────────────────────
banner "DEMO 3 — Deep Fingerprint (Ollama)"
echo -e "${CYAN}Command:${RESET} aasm fingerprint http://localhost:11434"
pause
aasm fingerprint http://localhost:11434

# ─────────────────────────────────────
banner "DEMO 4 — MCP Server Audit"
echo -e "${CYAN}Command:${RESET} aasm mcp 127.0.0.1 --ports 3001"
pause
aasm mcp 127.0.0.1 --ports 3001

# ─────────────────────────────────────
banner "DEMO 5 — Security Assessment (Prompt Injection)"
echo -e "${CYAN}Command:${RESET} aasm assess http://localhost:11434"
echo -e "${RED}⚠ Only run against systems you own.${RESET}"
pause
aasm assess http://localhost:11434 \
  --prompt-injection \
  --prompt-leakage \
  --max-payloads 5

# ─────────────────────────────────────
banner "DEMO 6 — Full Audit (LiteLLM)"
echo -e "${CYAN}Command:${RESET} aasm audit http://localhost:4000"
pause
aasm audit http://localhost:4000

# ─────────────────────────────────────
banner "DEMO 7 — AI Agent Analysis"
echo -e "${CYAN}Command:${RESET} aasm agents 127.0.0.1 --ports 3002"
pause
aasm agents 127.0.0.1 --ports 3002

# ─────────────────────────────────────
banner "DEMO 8 — Risk Score & Executive Summary"
LATEST_JSON=$(ls -t demo_reports/aasm_report_*.json 2>/dev/null | head -1)
if [ -n "$LATEST_JSON" ]; then
  echo -e "${CYAN}Command:${RESET} aasm risk $LATEST_JSON"
  pause
  aasm risk "$LATEST_JSON"
fi

# ─────────────────────────────────────
banner "DEMO 9 — Generate Infrastructure Graph"
if [ -n "$LATEST_JSON" ]; then
  echo -e "${CYAN}Command:${RESET} aasm graph $LATEST_JSON"
  pause
  aasm graph "$LATEST_JSON" --formats dot,mermaid
fi

# ─────────────────────────────────────
banner "DEMO 10 — Supported Platforms"
echo -e "${CYAN}Command:${RESET} aasm platforms"
pause
aasm platforms

echo ""
echo -e "${GREEN}✓ Demo complete! Reports saved in ./demo_reports/${RESET}"
echo -e "${GREEN}  Open ./demo_reports/*.html in your browser to see the full report.${RESET}"
