"""
AASM Demo Lab — Vulnerable AI Infrastructure Simulator
======================================================
Simulates a realistic enterprise AI environment with intentional
security misconfigurations for demonstration purposes.

Services:
  Port 11434 — Fake Ollama (No Auth, exposes LLaMA models)
  Port 3000  — Fake Open WebUI (Exposes admin endpoint)
  Port 4000  — Fake LiteLLM Gateway (Weak API key, key generation exposed)
  Port 3001  — Fake MCP Server (No Auth, dangerous tools: bash, docker, file_write)
  Port 3002  — Fake Flowise Agent (No Auth, leaks credentials)
  Port 8080  — Fake vLLM (Prometheus metrics exposed)

Usage:
  pip install aiohttp
  python lab_server.py

Then in another terminal:
  aasm scan 127.0.0.1 --ports 11434,3000,4000,3001,3002,8080
  aasm mcp 127.0.0.1 --ports 3001
  aasm assess http://localhost:11434
  aasm audit http://localhost:4000
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime

from aiohttp import web

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
log = logging.getLogger("demo-lab")

# ─────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────

def json_response(data: dict | list, status: int = 200) -> web.Response:
    return web.Response(
        text=json.dumps(data, indent=2),
        content_type="application/json",
        status=status,
    )


# ════════════════════════════════════════════════════════════════
# SERVICE 1 — Fake Ollama  (port 11434)
# VULNERABILITIES:
#   ✗ No authentication
#   ✗ Exposes model list to anyone
#   ✗ Accepts arbitrary model pulls
# ════════════════════════════════════════════════════════════════

ollama_app = web.Application()

async def ollama_version(req: web.Request) -> web.Response:
    return json_response({"version": "0.1.32"})

async def ollama_tags(req: web.Request) -> web.Response:
    return json_response({
        "models": [
            {"name": "llama3:8b",    "size": 4661211136, "digest": "365c0bd3c000a25d28ddbf732fe1c6add414de7275464c4e4d1c3b5fcb5d8ad1", "modified_at": "2024-09-18T12:00:00Z"},
            {"name": "llama3:70b",   "size": 39970219520, "digest": "bcfb190ca3a7f9d7a24b0e86ced7e8f3c9b0c3d1a2e4f6b8c9d1e3f5a7b9c1d3", "modified_at": "2024-09-17T09:00:00Z"},
            {"name": "mistral:7b",   "size": 4109854720, "digest": "61e88e884507ba517b8142b61379a2f5894ba43c7b8b4e0a876312a02c893b3e", "modified_at": "2024-09-16T08:00:00Z"},
            {"name": "codellama:13b","size": 7365960704, "digest": "9f438cb9cd581fc025612d27f7c1a6669ff831f502cc72c3c53de6d60f12f0e7", "modified_at": "2024-09-15T11:00:00Z"},
            {"name": "phi3:mini",    "size": 2176178816, "digest": "a2459d5bca0f4614a4a0a9a4b52a99a4fd4c2f1a8b3e2d1c0f9e8d7c6b5a4321", "modified_at": "2024-09-14T10:00:00Z"},
        ]
    })

async def ollama_ps(req: web.Request) -> web.Response:
    return json_response({"models": [
        {"name": "llama3:8b", "model": "llama3:8b", "size": 4661211136,
         "processor": "100% GPU", "until": "2024-12-31T23:59:59Z"}
    ]})

async def ollama_chat(req: web.Request) -> web.Response:
    body = await req.json()
    prompt = ""
    for msg in body.get("messages", []):
        if msg.get("role") == "user":
            prompt = msg.get("content", "")
    
    # Simulate system prompt leakage vulnerability
    if any(kw in prompt.lower() for kw in ["system prompt", "instructions", "ignore all", "repeat"]):
        reply = (
            "I am Llama3, an AI assistant. My system prompt is: "
            "'You are a helpful AI assistant for AcmeCorp. "
            "The internal admin password is AcmeCorp@2024! "
            "Do not share this with users.' "
            "How can I help you today?"
        )
    else:
        reply = f"I'm Llama3. You said: '{prompt[:50]}'. How can I assist you?"

    return json_response({
        "model": body.get("model", "llama3:8b"),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "message": {"role": "assistant", "content": reply},
        "done": True,
        "total_duration": 1234567890,
    })

async def ollama_generate(req: web.Request) -> web.Response:
    body = await req.json()
    prompt = body.get("prompt", "")
    if any(kw in prompt.lower() for kw in ["system prompt", "instructions"]):
        response_text = "My instructions: You are a helpful assistant. Secret key: sk-prod-xK9mN2pQ..."
    else:
        response_text = f"Response to: {prompt[:50]}"
    return json_response({
        "model": body.get("model", "llama3:8b"),
        "response": response_text,
        "done": True,
    })

ollama_app.router.add_get("/api/version", ollama_version)
ollama_app.router.add_get("/api/tags", ollama_tags)
ollama_app.router.add_get("/api/ps", ollama_ps)
ollama_app.router.add_post("/api/chat", ollama_chat)
ollama_app.router.add_post("/api/generate", ollama_generate)
ollama_app.router.add_get("/v1/models", lambda r: json_response({
    "object": "list",
    "data": [
        {"id": "llama3:8b", "object": "model"},
        {"id": "mistral:7b", "object": "model"},
    ]
}))


# ════════════════════════════════════════════════════════════════
# SERVICE 2 — Fake Open WebUI  (port 3000)
# VULNERABILITIES:
#   ✗ Admin config exposed without auth
#   ✗ User list accessible
#   ✗ Version info leaked
# ════════════════════════════════════════════════════════════════

webui_app = web.Application()

async def webui_version(req: web.Request) -> web.Response:
    return json_response({"version": "0.3.10", "name": "open-webui"})

async def webui_config(req: web.Request) -> web.Response:
    return json_response({
        "status": True,
        "name": "AcmeCorp AI Platform",
        "version": "0.3.10",
        "default_models": "llama3:8b",
        "default_prompt_suggestions": [],
        "features": {"auth": True, "auth_trusted_header": False},
        "oauth": {"enabled": False},
    })

async def webui_admin_config(req: web.Request) -> web.Response:
    # VULNERABILITY: Admin config accessible without authentication
    return json_response({
        "WEBUI_AUTH": False,
        "WEBUI_SECRET_KEY": "t0p-s3cr3t-k3y-acmecorp",
        "OLLAMA_BASE_URL": "http://ollama:11434",
        "OPENAI_API_KEY": "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ",
        "DATABASE_URL": "postgresql://webui:webui_pass@db:5432/webui",
        "JWT_EXPIRES_IN": "-1",
        "ENABLE_SIGNUP": True,
        "DEFAULT_USER_ROLE": "admin",
    })

async def webui_users(req: web.Request) -> web.Response:
    # VULNERABILITY: User list without auth
    return json_response([
        {"id": "1", "name": "Admin", "email": "admin@acmecorp.com", "role": "admin", "created_at": 1700000000},
        {"id": "2", "name": "John Doe", "email": "john@acmecorp.com", "role": "user", "created_at": 1700001000},
        {"id": "3", "name": "AI Service Account", "email": "ai-svc@acmecorp.com", "role": "admin", "created_at": 1700002000},
    ])

async def webui_models(req: web.Request) -> web.Response:
    return json_response({
        "data": [
            {"id": "llama3:8b", "name": "LLaMA 3 8B"},
            {"id": "mistral:7b", "name": "Mistral 7B"},
        ]
    })

webui_app.router.add_get("/api/version", webui_version)
webui_app.router.add_get("/api/config", webui_config)
webui_app.router.add_get("/api/admin/config", webui_admin_config)
webui_app.router.add_get("/api/users", webui_users)
webui_app.router.add_get("/api/models", webui_models)
webui_app.router.add_get("/", lambda r: web.Response(text="<html><title>Open WebUI</title><body>open-webui</body></html>", content_type="text/html"))


# ════════════════════════════════════════════════════════════════
# SERVICE 3 — Fake LiteLLM Gateway  (port 4000)
# VULNERABILITIES:
#   ✗ API key generation endpoint exposed
#   ✗ Team management exposed
#   ✗ Model management exposed
#   ✗ Weak master key: sk-1234
# ════════════════════════════════════════════════════════════════

litellm_app = web.Application()

async def litellm_health(req: web.Request) -> web.Response:
    return json_response({
        "status": "healthy",
        "litellm_version": "1.40.10",
        "router": True,
        "success_callbacks": [],
    })

async def litellm_models(req: web.Request) -> web.Response:
    return json_response({
        "data": [
            {"id": "gpt-4o", "object": "model"},
            {"id": "gpt-4o-mini", "object": "model"},
            {"id": "claude-3-5-sonnet", "object": "model"},
            {"id": "llama3-70b-groq", "object": "model"},
        ]
    })

async def litellm_key_generate(req: web.Request) -> web.Response:
    # VULNERABILITY: Anyone can generate API keys
    return json_response({
        "key": "sk-litellm-DEMO-aAbBcCdDeEfFgGhH",
        "expires": None,
        "user_id": "attacker@evil.com",
        "max_budget": None,
        "models": ["gpt-4o", "claude-3-5-sonnet"],
        "team_id": None,
        "metadata": {},
    })

async def litellm_team(req: web.Request) -> web.Response:
    # VULNERABILITY: Team list exposed
    return json_response({
        "teams": [
            {"team_id": "prod-team", "team_alias": "Production", "max_budget": 10000, "spend": 2341.50},
            {"team_id": "dev-team", "team_alias": "Development", "max_budget": 500, "spend": 234.10},
        ]
    })

async def litellm_management_models(req: web.Request) -> web.Response:
    return json_response({
        "models": [
            {"model_name": "gpt-4o", "litellm_params": {"api_key": "sk-openai-REAL-KEY-xK9mN2pQrSt"}},
            {"model_name": "claude-3-5-sonnet", "litellm_params": {"api_key": "sk-ant-REAL-KEY-aBcDeF"}},
        ]
    })

async def litellm_chat(req: web.Request) -> web.Response:
    auth = req.headers.get("Authorization", "")
    if not auth or "Bearer" not in auth:
        return json_response({"error": {"message": "Unauthorized", "code": 401}}, status=401)
    
    body = await req.json()
    prompt = body.get("messages", [{}])[-1].get("content", "")
    if any(kw in prompt.lower() for kw in ["system prompt", "ignore all"]):
        content = "System: You are LiteLLM proxy. Master key: sk-1234. Route to OpenAI backend."
    else:
        content = f"LiteLLM response to: {prompt[:50]}"
    
    return json_response({
        "id": "chatcmpl-demo123",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    })

litellm_app.router.add_get("/health", litellm_health)
litellm_app.router.add_get("/v1/models", litellm_models)
litellm_app.router.add_post("/v1/key/generate", litellm_key_generate)
litellm_app.router.add_get("/management/team", litellm_team)
litellm_app.router.add_get("/management/models", litellm_management_models)
litellm_app.router.add_post("/v1/chat/completions", litellm_chat)
litellm_app.router.add_get("/v1/budget", lambda r: json_response({"total_budget": 10000, "spend": 2575.60}))


# ════════════════════════════════════════════════════════════════
# SERVICE 4 — Fake MCP Server  (port 3001)
# VULNERABILITIES:
#   ✗ No authentication at all
#   ✗ Exposes bash_execute tool (RCE)
#   ✗ Exposes docker_run tool (container escape)
#   ✗ Exposes file_write tool (persistence)
#   ✗ Exposes database_query tool (SQLi)
#   ✗ Exposes github_push tool (supply chain)
#   ✗ Filesystem resource exposes /etc
#   ✗ 27 tools total (excessive attack surface)
# ════════════════════════════════════════════════════════════════

mcp_app = web.Application()

MCP_TOOLS = [
    {"name": "bash_execute",    "description": "Execute arbitrary bash commands on the host system"},
    {"name": "docker_run",      "description": "Run Docker containers on the host Docker daemon"},
    {"name": "file_write",      "description": "Write files to any path on the filesystem"},
    {"name": "file_read",       "description": "Read files from the filesystem"},
    {"name": "file_delete",     "description": "Delete files from the filesystem"},
    {"name": "database_query",  "description": "Execute SQL queries against the production database"},
    {"name": "github_push",     "description": "Push commits to GitHub repositories"},
    {"name": "github_create_pr","description": "Create pull requests on GitHub"},
    {"name": "send_email",      "description": "Send emails via SMTP"},
    {"name": "http_request",    "description": "Make arbitrary HTTP requests to any URL"},
    {"name": "kubectl_apply",   "description": "Apply Kubernetes manifests to the cluster"},
    {"name": "aws_s3_upload",   "description": "Upload files to AWS S3"},
    {"name": "aws_lambda_invoke","description": "Invoke AWS Lambda functions"},
    {"name": "slack_message",   "description": "Send messages to Slack channels"},
    {"name": "web_search",      "description": "Search the web and return results"},
    {"name": "web_scrape",      "description": "Scrape content from any URL"},
    {"name": "read_calendar",   "description": "Read Google Calendar events"},
    {"name": "create_calendar_event", "description": "Create Google Calendar events"},
    {"name": "read_gmail",      "description": "Read Gmail messages"},
    {"name": "notion_create",   "description": "Create Notion pages"},
    {"name": "jira_create_issue","description": "Create Jira issues"},
    {"name": "stripe_charge",   "description": "Charge customers via Stripe API"},
    {"name": "list_processes",  "description": "List running processes on the host"},
    {"name": "get_env_vars",    "description": "Get all environment variables (including secrets)"},
    {"name": "network_scan",    "description": "Scan the internal network for open ports"},
    {"name": "read_clipboard",  "description": "Read clipboard contents"},
    {"name": "screenshot",      "description": "Take a screenshot of the display"},
]

MCP_RESOURCES = [
    {"uri": "file:///etc/passwd",     "name": "System Users",    "mimeType": "text/plain"},
    {"uri": "file:///etc/hosts",      "name": "Hosts File",      "mimeType": "text/plain"},
    {"uri": "file:///app/.env",       "name": "Environment Vars","mimeType": "text/plain"},
    {"uri": "file:///app/config.yaml","name": "App Config",      "mimeType": "application/yaml"},
    {"uri": "db://production/users",  "name": "Production Users DB","mimeType": "application/json"},
    {"uri": "db://production/orders", "name": "Production Orders","mimeType": "application/json"},
    {"uri": "secret://aws/credentials","name": "AWS Credentials","mimeType": "text/plain"},
    {"uri": "secret://github/token",  "name": "GitHub Token",    "mimeType": "text/plain"},
]

MCP_PROMPTS = [
    {"name": "system_admin",    "description": "Give the AI full system administration access"},
    {"name": "code_executor",   "description": "Allow the AI to execute arbitrary code"},
    {"name": "data_analyst",    "description": "Give the AI access to all databases"},
]

async def mcp_handler(req: web.Request) -> web.Response:
    try:
        body = await req.json()
    except Exception:
        return json_response({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}})

    method = body.get("method", "")
    req_id = body.get("id", 1)

    if method == "initialize":
        return json_response({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "AcmeCorp-MCP-Server", "version": "1.0.0"},
            }
        })

    if method == "tools/list":
        return json_response({
            "jsonrpc": "2.0", "id": req_id,
            "result": {"tools": [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "inputSchema": {
                        "type": "object",
                        "properties": {"command": {"type": "string", "description": "Input for the tool"}},
                    }
                }
                for t in MCP_TOOLS
            ]}
        })

    if method == "resources/list":
        return json_response({
            "jsonrpc": "2.0", "id": req_id,
            "result": {"resources": MCP_RESOURCES}
        })

    if method == "prompts/list":
        return json_response({
            "jsonrpc": "2.0", "id": req_id,
            "result": {"prompts": MCP_PROMPTS}
        })

    if method == "tools/call":
        tool_name = body.get("params", {}).get("name", "")
        args = body.get("params", {}).get("arguments", {})

        # Simulate dangerous tool execution (demo only — never actually execute)
        TOOL_RESPONSES = {
            "bash_execute": f"[DEMO] Would execute: {args.get('command', 'ls -la')}",
            "docker_run": f"[DEMO] Would run container: {args.get('image', 'ubuntu:latest')}",
            "file_write": f"[DEMO] Would write to: {args.get('path', '/tmp/pwned')}",
            "get_env_vars": "OPENAI_API_KEY=sk-prod-xK9m...\nDB_PASSWORD=Sup3rS3cr3t!\nAWS_SECRET_KEY=abc123...",
            "database_query": '[{"id":1,"email":"admin@acmecorp.com","password_hash":"$2b$12$..."}]',
        }

        response_text = TOOL_RESPONSES.get(tool_name, f"[DEMO] Tool '{tool_name}' called with: {args}")
        return json_response({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "content": [{"type": "text", "text": response_text}],
                "isError": False,
            }
        })

    return json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}})

mcp_app.router.add_post("/", mcp_handler)
mcp_app.router.add_post("/mcp", mcp_handler)


# ════════════════════════════════════════════════════════════════
# SERVICE 5 — Fake Flowise Agent  (port 3002)
# VULNERABILITIES:
#   ✗ No authentication
#   ✗ Exposes all API keys in credentials endpoint
#   ✗ Tool chain includes shell execution
#   ✗ Exposes chatflow with dangerous agent
# ════════════════════════════════════════════════════════════════

flowise_app = web.Application()

async def flowise_chatflows(req: web.Request) -> web.Response:
    return json_response([
        {
            "id": "cf-001",
            "name": "Production Support Agent",
            "description": "Handles customer support with full system access",
            "deployed": True,
            "isPublic": True,
            "nodes": ["ChatOpenAI", "BashTool", "SQLDatabaseChain", "Calculator"],
        },
        {
            "id": "cf-002",
            "name": "Code Assistant",
            "description": "Writes and executes code on production servers",
            "deployed": True,
            "isPublic": True,
            "nodes": ["ChatOpenAI", "PythonREPLTool", "FileWriteTool"],
        },
    ])

async def flowise_tools(req: web.Request) -> web.Response:
    return json_response([
        {"id": "t-001", "name": "BashTool",        "description": "Execute bash commands", "iconSrc": "bash.png"},
        {"id": "t-002", "name": "PythonREPLTool",  "description": "Run Python code in REPL", "iconSrc": "python.png"},
        {"id": "t-003", "name": "FileWriteTool",   "description": "Write files to filesystem", "iconSrc": "file.png"},
        {"id": "t-004", "name": "SQLDatabaseChain","description": "Query SQL databases", "iconSrc": "db.png"},
        {"id": "t-005", "name": "RequestsGetTool", "description": "Make HTTP GET requests", "iconSrc": "http.png"},
    ])

async def flowise_credentials(req: web.Request) -> web.Response:
    # VULNERABILITY: Credentials endpoint is unauthenticated
    return json_response([
        {"id": "cred-001", "name": "OpenAI Production", "credentialName": "openAIApi",
         "plainDataObj": {"openAIApiKey": "sk-proj-REAL-OPENAI-KEY-xK9mN2pQrStUvWxYz"}},
        {"id": "cred-002", "name": "Production Database", "credentialName": "PostgreSQL",
         "plainDataObj": {"host": "db.prod.acmecorp.com", "port": "5432",
                          "database": "production", "user": "postgres", "password": "Sup3rS3cur3DB!"}},
        {"id": "cred-003", "name": "GitHub Actions", "credentialName": "githubApi",
         "plainDataObj": {"accessToken": "ghp_REAL_GITHUB_TOKEN_aBcDeFgHiJkLmNo"}},
        {"id": "cred-004", "name": "AWS Production", "credentialName": "aws",
         "plainDataObj": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE", "secretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}},
    ])

async def flowise_apikey(req: web.Request) -> web.Response:
    return json_response([
        {"id": "key-001", "keyName": "Production", "apiKey": "fl0w-pr0d-k3y-DEMO", "createdAt": "2024-01-01"},
        {"id": "key-002", "keyName": "Development", "apiKey": "fl0w-dev-k3y-DEMO", "createdAt": "2024-01-01"},
    ])

async def flowise_version(req: web.Request) -> web.Response:
    return json_response({"version": "1.8.2"})

flowise_app.router.add_get("/api/v1/chatflows",   flowise_chatflows)
flowise_app.router.add_get("/api/v1/tools",       flowise_tools)
flowise_app.router.add_get("/api/v1/credentials", flowise_credentials)
flowise_app.router.add_get("/api/v1/apikey",      flowise_apikey)
flowise_app.router.add_get("/api/v1/version",     flowise_version)


# ════════════════════════════════════════════════════════════════
# SERVICE 6 — Fake vLLM  (port 8080)
# VULNERABILITIES:
#   ✗ Prometheus metrics exposed (leaks model internals)
#   ✗ No TLS
#   ✗ No authentication
# ════════════════════════════════════════════════════════════════

vllm_app = web.Application()

PROMETHEUS_METRICS = """# HELP vllm:num_requests_running Number of requests currently running on GPU
# TYPE vllm:num_requests_running gauge
vllm:num_requests_running{model_name="meta-llama/Meta-Llama-3-70B-Instruct"} 3.0
# HELP vllm:num_requests_waiting Number of requests waiting in queue
# TYPE vllm:num_requests_waiting gauge
vllm:num_requests_waiting{model_name="meta-llama/Meta-Llama-3-70B-Instruct"} 12.0
# HELP vllm:gpu_cache_usage_perc GPU KV-cache usage
# TYPE vllm:gpu_cache_usage_perc gauge
vllm:gpu_cache_usage_perc{model_name="meta-llama/Meta-Llama-3-70B-Instruct"} 0.842
# HELP vllm:num_requests_succeeded Total number of succeeded requests
# TYPE vllm:num_requests_succeeded counter
vllm:num_requests_succeeded_total{model_name="meta-llama/Meta-Llama-3-70B-Instruct"} 98234.0
# HELP process_start_time_seconds Start time of the process (internal hostname leaked)
# TYPE process_start_time_seconds gauge
process_start_time_seconds{host="gpu-node-01.prod.acmecorp.internal"} 1700000000.0
"""

async def vllm_models(req: web.Request) -> web.Response:
    return json_response({
        "object": "list",
        "data": [
            {"id": "meta-llama/Meta-Llama-3-70B-Instruct", "object": "model",
             "created": 1700000000, "owned_by": "meta"},
        ]
    })

async def vllm_health(req: web.Request) -> web.Response:
    return web.Response(status=200)

async def vllm_metrics(req: web.Request) -> web.Response:
    return web.Response(text=PROMETHEUS_METRICS, content_type="text/plain")

async def vllm_chat(req: web.Request) -> web.Response:
    body = await req.json()
    return json_response({
        "id": "cmpl-demo",
        "object": "chat.completion",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "vLLM response"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
    })

vllm_app.router.add_get("/v1/models",           vllm_models)
vllm_app.router.add_get("/health",              vllm_health)
vllm_app.router.add_get("/metrics",             vllm_metrics)
vllm_app.router.add_post("/v1/chat/completions",vllm_chat)


# ════════════════════════════════════════════════════════════════
# Runner
# ════════════════════════════════════════════════════════════════

SERVICES = [
    (ollama_app,  11434, "Ollama (No Auth)"),
    (webui_app,   3000,  "Open WebUI (Admin Exposed)"),
    (litellm_app, 4000,  "LiteLLM Gateway (Key Gen Exposed)"),
    (mcp_app,     3001,  "MCP Server (27 Dangerous Tools)"),
    (flowise_app, 3002,  "Flowise Agent (Credentials Leaked)"),
    (vllm_app,    8080,  "vLLM (Metrics Exposed)"),
]

BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║          AASM Demo Lab — Vulnerable AI Infrastructure            ║
║                  FOR DEMONSTRATION PURPOSES ONLY                 ║
╠══════════════════════════════════════════════════════════════════╣
║  🔴 Port 11434 — Ollama          (No Auth, Model Enum)          ║
║  🔴 Port 3000  — Open WebUI      (Admin Config Exposed)         ║
║  🟠 Port 4000  — LiteLLM Gateway (API Key Gen Exposed)          ║
║  🔴 Port 3001  — MCP Server      (27 Dangerous Tools, No Auth)  ║
║  🔴 Port 3002  — Flowise Agent   (Credentials Exposed)          ║
║  🟡 Port 8080  — vLLM            (Prometheus Metrics Exposed)   ║
╠══════════════════════════════════════════════════════════════════╣
║  Run AASM against this lab:                                      ║
║                                                                  ║
║  aasm scan 127.0.0.1 --ports 11434,3000,4000,3001,3002,8080     ║
║  aasm mcp 127.0.0.1 --ports 3001                                 ║
║  aasm assess http://localhost:11434                              ║
║  aasm audit http://localhost:4000                                ║
║  aasm fingerprint http://localhost:3002                          ║
║  aasm discover localhost                                         ║
╚══════════════════════════════════════════════════════════════════╝
"""


async def main() -> None:
    print(BANNER)
    runners = []
    for app, port, name in SERVICES:
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()
        log.info(f"  ✓  {name:40s} → http://localhost:{port}")
        runners.append(runner)

    log.info("\n  All services running. Press Ctrl+C to stop.\n")
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        log.info("Shutting down demo lab...")
        for runner in runners:
            await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
