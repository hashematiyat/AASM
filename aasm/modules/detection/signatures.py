"""
Platform detection signatures — HTTP headers, JSON keys, HTML patterns,
favicon hashes, cookie names, URL patterns, error signatures.
Each entry drives the confidence-based multi-signal detection engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlatformSignature:
    """All known detection signals for a single AI platform."""
    platform: str
    header_signals: list[dict[str, str]] = field(default_factory=list)
    json_signals: list[str] = field(default_factory=list)
    html_signals: list[str] = field(default_factory=list)
    path_signals: list[str] = field(default_factory=list)
    cookie_signals: list[str] = field(default_factory=list)
    error_signals: list[str] = field(default_factory=list)
    favicon_hashes: list[str] = field(default_factory=list)
    js_signals: list[str] = field(default_factory=list)
    graphql_signals: list[str] = field(default_factory=list)
    openapi_signals: list[str] = field(default_factory=list)
    probe_paths: list[str] = field(default_factory=list)
    signal_weights: dict[str, float] = field(default_factory=dict)


PLATFORM_SIGNATURES: dict[str, PlatformSignature] = {

    "Ollama": PlatformSignature(
        platform="Ollama",
        probe_paths=["/api/version", "/api/tags"],
        header_signals=[
            {"server": "ollama"},
        ],
        json_signals=[
            "version",       # /api/version returns {"version": "..."}
            "models",        # /api/tags returns {"models": [...]}
            "model_info",
        ],
        html_signals=[
            "Ollama",
            "ollama",
        ],
        path_signals=[
            "/api/version",
            "/api/tags",
            "/api/ps",
            "/api/generate",
            "/api/chat",
            "/api/embeddings",
        ],
        error_signals=[
            "ollama",
            "model not found",
        ],
        signal_weights={
            "header": 0.40,
            "json": 0.35,
            "path": 0.15,
            "error": 0.10,
        },
    ),

    "Open WebUI": PlatformSignature(
        platform="Open WebUI",
        probe_paths=["/api/version", "/api/config"],
        header_signals=[
            {"x-openwebui-version": ""},
            {"server": "openwebui"},
        ],
        html_signals=[
            "Open WebUI",
            "openwebui",
            "open-webui",
            "SvelteKit",
        ],
        json_signals=[
            "version",
            "commit",
            "features",
        ],
        path_signals=[
            "/api/version",
            "/api/config",
            "/api/models",
            "/api/users",
            "/api/admin/config",
        ],
        cookie_signals=[
            "openwebui-session",
            "openwebui-token",
        ],
        js_signals=[
            "open-webui",
            "openwebui",
        ],
        signal_weights={
            "html": 0.35,
            "header": 0.30,
            "path": 0.20,
            "cookie": 0.15,
        },
    ),

    "LiteLLM": PlatformSignature(
        platform="LiteLLM",
        probe_paths=["/health", "/v1/models"],
        header_signals=[
            {"server": "litellm"},
            {"x-litellm-version": ""},
        ],
        json_signals=[
            "litellm_version",
            "router_model_names",
            "healthy_endpoints",
            "unhealthy_endpoints",
        ],
        html_signals=[
            "LiteLLM",
            "litellm",
        ],
        path_signals=[
            "/health",
            "/v1/models",
            "/v1/budget",
            "/management/models",
            "/management/team",
            "/v1/key/generate",
        ],
        openapi_signals=[
            "LiteLLM",
            "litellm",
        ],
        signal_weights={
            "json": 0.40,
            "header": 0.30,
            "path": 0.20,
            "html": 0.10,
        },
    ),

    "vLLM": PlatformSignature(
        platform="vLLM",
        probe_paths=["/v1/models", "/health"],
        header_signals=[
            {"server": "vllm"},
            {"x-powered-by": "vllm"},
        ],
        json_signals=[
            "max_model_len",
            "gpu_memory_utilization",
        ],
        path_signals=[
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/health",
            "/metrics",
        ],
        error_signals=[
            "vllm",
            "ray",
        ],
        openapi_signals=[
            "vLLM",
            "vllm",
        ],
        signal_weights={
            "header": 0.45,
            "json": 0.30,
            "path": 0.15,
            "error": 0.10,
        },
    ),

    "LM Studio": PlatformSignature(
        platform="LM Studio",
        probe_paths=["/v1/models"],
        header_signals=[
            {"server": "lmstudio"},
            {"x-lm-studio-server": ""},
        ],
        json_signals=[
            "lm_studio",
            "lmstudio",
        ],
        path_signals=[
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
        ],
        error_signals=[
            "lm studio",
            "lmstudio",
        ],
        signal_weights={
            "header": 0.50,
            "json": 0.25,
            "path": 0.15,
            "error": 0.10,
        },
    ),

    "Flowise": PlatformSignature(
        platform="Flowise",
        probe_paths=["/api/v1/chatflows", "/api/v1/tools"],
        header_signals=[
            {"server": "flowise"},
            {"x-powered-by": "Express"},
        ],
        html_signals=[
            "Flowise",
            "flowise",
            "FlowiseAI",
        ],
        json_signals=[
            "chatflows",
            "chatflowId",
            "flowData",
            "tools",
        ],
        path_signals=[
            "/api/v1/chatflows",
            "/api/v1/tools",
            "/api/v1/credentials",
            "/api/v1/variables",
            "/api/v1/apikey",
            "/api/v1/stats",
            "/api/v1/version",
        ],
        favicon_hashes=[
            "flowise-favicon",
        ],
        js_signals=[
            "flowise",
            "FlowiseAI",
        ],
        signal_weights={
            "path": 0.35,
            "json": 0.30,
            "html": 0.25,
            "header": 0.10,
        },
    ),

    "Dify": PlatformSignature(
        platform="Dify",
        probe_paths=["/api/version", "/console/api/setup", "/v1/info"],
        header_signals=[
            {"server": "dify"},
            {"x-dify-version": ""},
        ],
        html_signals=[
            "Dify",
            "dify",
            "difyai",
        ],
        json_signals=[
            "dify_version",
            "edition",
            "apps",
            "datasets",
        ],
        path_signals=[
            "/api/version",
            "/console/api/setup",
            "/v1/info",
            "/console/api/apps",
            "/v1/chat-messages",
            "/v1/workflows/run",
        ],
        cookie_signals=[
            "dify-session",
        ],
        js_signals=[
            "dify",
            "__dify__",
        ],
        signal_weights={
            "json": 0.35,
            "html": 0.30,
            "path": 0.25,
            "header": 0.10,
        },
    ),

    "Langflow": PlatformSignature(
        platform="Langflow",
        probe_paths=["/api/v1/version", "/health"],
        header_signals=[
            {"server": "langflow"},
            {"x-powered-by": "Langflow"},
        ],
        html_signals=[
            "Langflow",
            "langflow",
        ],
        json_signals=[
            "version",
            "langflow",
            "components",
            "flows",
        ],
        path_signals=[
            "/api/v1/version",
            "/api/v1/flows",
            "/api/v1/components",
            "/health",
            "/api/v1/config",
        ],
        js_signals=[
            "langflow",
        ],
        openapi_signals=[
            "Langflow",
            "langflow",
        ],
        signal_weights={
            "json": 0.35,
            "html": 0.25,
            "path": 0.25,
            "header": 0.15,
        },
    ),

    "AnythingLLM": PlatformSignature(
        platform="AnythingLLM",
        probe_paths=["/api/ping", "/api/system-settings"],
        header_signals=[
            {"server": "anythingllm"},
        ],
        html_signals=[
            "AnythingLLM",
            "anythingllm",
            "anything-llm",
            "AnythingLLM — LLM Chat",
        ],
        json_signals=[
            "pong",
            "workspace",
            "settings",
        ],
        path_signals=[
            "/api/ping",
            "/api/system-settings",
            "/api/workspaces",
            "/api/users",
            "/api/system-vectors",
        ],
        js_signals=[
            "anythingllm",
            "anything-llm",
        ],
        signal_weights={
            "html": 0.40,
            "path": 0.30,
            "json": 0.20,
            "header": 0.10,
        },
    ),

    "LocalAI": PlatformSignature(
        platform="LocalAI",
        probe_paths=["/v1/models", "/models"],
        header_signals=[
            {"server": "localai"},
            {"x-localai-version": ""},
        ],
        json_signals=[
            "localai",
            "backends",
            "gallery",
        ],
        path_signals=[
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "/v1/images/generations",
            "/v1/audio/transcriptions",
            "/models",
            "/backend-monitor",
        ],
        error_signals=[
            "localai",
        ],
        signal_weights={
            "header": 0.40,
            "path": 0.30,
            "json": 0.20,
            "error": 0.10,
        },
    ),

    "HuggingFace TGI": PlatformSignature(
        platform="HuggingFace TGI",
        probe_paths=["/info", "/metrics"],
        header_signals=[
            {"server": "text-generation-inference"},
            {"x-tgi-version": ""},
        ],
        json_signals=[
            "model_id",
            "model_dtype",
            "model_device_type",
            "max_total_tokens",
            "max_best_of",
            "sha",
            "docker_label",
        ],
        path_signals=[
            "/info",
            "/metrics",
            "/generate",
            "/generate_stream",
            "/v1/chat/completions",
            "/v1/models",
            "/health",
            "/tokenize",
        ],
        openapi_signals=[
            "Text Generation Inference",
            "tgi",
        ],
        signal_weights={
            "header": 0.40,
            "json": 0.35,
            "path": 0.15,
            "openapi": 0.10,
        },
    ),

    "OpenRouter": PlatformSignature(
        platform="OpenRouter",
        probe_paths=["/api/v1/models", "/v1/models"],
        header_signals=[
            {"server": "openrouter"},
            {"x-openrouter-version": ""},
        ],
        json_signals=[
            "openrouter",
            "pricing",
            "top_provider",
            "per_request_limits",
        ],
        path_signals=[
            "/api/v1/models",
            "/api/v1/chat/completions",
            "/api/v1/generation",
            "/v1/models",
        ],
        signal_weights={
            "header": 0.45,
            "json": 0.35,
            "path": 0.20,
        },
    ),

    "OpenAI Compatible": PlatformSignature(
        platform="OpenAI Compatible",
        probe_paths=["/v1/models"],
        json_signals=[
            "object",
            "data",
            "owned_by",
        ],
        path_signals=[
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
        ],
        signal_weights={
            "json": 0.50,
            "path": 0.50,
        },
    ),

    "CrewAI": PlatformSignature(
        platform="CrewAI",
        probe_paths=["/api/health", "/api/crews", "/health"],
        header_signals=[
            {"server": "crewai"},
            {"x-crewai-version": ""},
        ],
        html_signals=[
            "CrewAI",
            "crewai",
        ],
        json_signals=[
            "crews",
            "agents",
            "tasks",
            "crew_output",
        ],
        path_signals=[
            "/api/crews",
            "/api/agents",
            "/api/tasks",
            "/api/health",
            "/health",
        ],
        signal_weights={
            "json": 0.40,
            "path": 0.30,
            "header": 0.20,
            "html": 0.10,
        },
    ),

    "AutoGen": PlatformSignature(
        platform="AutoGen",
        probe_paths=["/api/health", "/health"],
        header_signals=[
            {"server": "autogen"},
            {"x-autogen-version": ""},
        ],
        html_signals=[
            "AutoGen",
            "autogen",
            "microsoft/autogen",
        ],
        json_signals=[
            "agents",
            "conversation",
            "groupchat",
            "autogen",
        ],
        path_signals=[
            "/api/agents",
            "/api/conversations",
            "/health",
        ],
        signal_weights={
            "html": 0.35,
            "json": 0.35,
            "path": 0.20,
            "header": 0.10,
        },
    ),

    "LangGraph": PlatformSignature(
        platform="LangGraph",
        probe_paths=["/ok", "/health"],
        header_signals=[
            {"server": "langgraph"},
            {"x-langgraph-version": ""},
        ],
        html_signals=[
            "LangGraph",
            "langgraph",
            "LangChain",
        ],
        json_signals=[
            "graphs",
            "threads",
            "assistants",
            "checkpoints",
            "runs",
        ],
        path_signals=[
            "/ok",
            "/graphs",
            "/threads",
            "/assistants",
            "/runs",
            "/store",
        ],
        openapi_signals=[
            "LangGraph",
            "langgraph",
        ],
        signal_weights={
            "json": 0.40,
            "path": 0.30,
            "header": 0.20,
            "html": 0.10,
        },
    ),

    "OpenHands": PlatformSignature(
        platform="OpenHands",
        probe_paths=["/api/options", "/health"],
        header_signals=[
            {"server": "openhands"},
            {"x-openhands-version": ""},
        ],
        html_signals=[
            "OpenHands",
            "openhands",
            "OpenDevin",
            "opendevin",
        ],
        json_signals=[
            "options",
            "provider",
            "model",
            "agent",
            "git_token",
        ],
        path_signals=[
            "/api/options",
            "/api/conversations",
            "/api/list-models",
            "/health",
            "/api/select-file",
            "/api/run",
        ],
        signal_weights={
            "html": 0.40,
            "json": 0.30,
            "path": 0.20,
            "header": 0.10,
        },
    ),

    "FastChat": PlatformSignature(
        platform="FastChat",
        probe_paths=["/v1/models", "/worker_get_status"],
        header_signals=[
            {"server": "fastchat"},
        ],
        html_signals=[
            "FastChat",
            "fastchat",
            "Vicuna",
        ],
        json_signals=[
            "worker_addr",
            "model_names",
            "speed",
            "queue_length",
        ],
        path_signals=[
            "/v1/models",
            "/v1/chat/completions",
            "/v1/completions",
            "/worker_get_status",
            "/worker_get_model_details",
            "/v1/embeddings",
        ],
        signal_weights={
            "json": 0.40,
            "path": 0.30,
            "html": 0.20,
            "header": 0.10,
        },
    ),

    "Text Generation WebUI": PlatformSignature(
        platform="Text Generation WebUI",
        probe_paths=["/api/v1/model", "/v1/models"],
        header_signals=[
            {"server": "oobabooga"},
        ],
        html_signals=[
            "Text Generation Web UI",
            "oobabooga",
            "text-generation-webui",
            "Gradio",
        ],
        json_signals=[
            "model_name",
            "lora_names",
            "shared.settings",
        ],
        path_signals=[
            "/api/v1/model",
            "/api/v1/generate",
            "/api/v1/chat",
            "/v1/models",
            "/v1/chat/completions",
            "/api/v1/token-count",
        ],
        js_signals=[
            "gradio",
            "oobabooga",
        ],
        signal_weights={
            "html": 0.40,
            "json": 0.25,
            "path": 0.25,
            "header": 0.10,
        },
    ),
}
