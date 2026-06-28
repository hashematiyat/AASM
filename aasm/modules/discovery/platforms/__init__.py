from .base import BasePlatformDetector
from .ollama import OllamaDetector
from .openwebui import OpenWebUIDetector
from .lmstudio import LMStudioDetector
from .litellm import LiteLLMDetector
from .vllm import VLLMDetector
from .huggingface import HuggingFaceTGIDetector
from .flowise import FlowiseDetector
from .openai_compat import OpenAICompatDetector
from .dify import DifyDetector
from .langflow import LangflowDetector
from .anythingllm import AnythingLLMDetector
from .localai import LocalAIDetector
from .openrouter import OpenRouterDetector
from .crewai import CrewAIDetector
from .autogen import AutoGenDetector
from .langgraph import LangGraphDetector
from .openhands import OpenHandsDetector
from .fastchat import FastChatDetector
from .textgen_webui import TextGenWebUIDetector

ALL_DETECTORS = [
    OllamaDetector,
    OpenWebUIDetector,
    LMStudioDetector,
    LiteLLMDetector,
    VLLMDetector,
    HuggingFaceTGIDetector,
    FlowiseDetector,
    DifyDetector,
    LangflowDetector,
    AnythingLLMDetector,
    LocalAIDetector,
    OpenRouterDetector,
    CrewAIDetector,
    AutoGenDetector,
    LangGraphDetector,
    OpenHandsDetector,
    FastChatDetector,
    TextGenWebUIDetector,
    OpenAICompatDetector,
]

__all__ = [
    "BasePlatformDetector",
    "OllamaDetector",
    "OpenWebUIDetector",
    "LMStudioDetector",
    "LiteLLMDetector",
    "VLLMDetector",
    "HuggingFaceTGIDetector",
    "FlowiseDetector",
    "DifyDetector",
    "LangflowDetector",
    "AnythingLLMDetector",
    "LocalAIDetector",
    "OpenRouterDetector",
    "CrewAIDetector",
    "AutoGenDetector",
    "LangGraphDetector",
    "OpenHandsDetector",
    "FastChatDetector",
    "TextGenWebUIDetector",
    "OpenAICompatDetector",
    "ALL_DETECTORS",
]
