"""
Tests for Feature 3 — AI Platform Support (new platform detectors)
"""

from __future__ import annotations

import pytest
import httpx

from aasm.modules.discovery.platforms import ALL_DETECTORS
from aasm.modules.discovery.platforms.dify import DifyDetector
from aasm.modules.discovery.platforms.langflow import LangflowDetector
from aasm.modules.discovery.platforms.anythingllm import AnythingLLMDetector
from aasm.modules.discovery.platforms.localai import LocalAIDetector
from aasm.modules.discovery.platforms.openrouter import OpenRouterDetector
from aasm.modules.discovery.platforms.crewai import CrewAIDetector
from aasm.modules.discovery.platforms.autogen import AutoGenDetector
from aasm.modules.discovery.platforms.langgraph import LangGraphDetector
from aasm.modules.discovery.platforms.openhands import OpenHandsDetector
from aasm.modules.discovery.platforms.fastchat import FastChatDetector
from aasm.modules.discovery.platforms.textgen_webui import TextGenWebUIDetector


class TestAllDetectorsRegistered:
    """Ensure all new detectors are registered in ALL_DETECTORS."""

    def test_all_detectors_count_increased(self):
        assert len(ALL_DETECTORS) > 10

    def test_dify_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "Dify" in names

    def test_langflow_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "Langflow" in names

    def test_anythingllm_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "AnythingLLM" in names

    def test_localai_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "LocalAI" in names

    def test_openrouter_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "OpenRouter" in names

    def test_crewai_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "CrewAI" in names

    def test_autogen_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "AutoGen" in names

    def test_langgraph_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "LangGraph" in names

    def test_openhands_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "OpenHands" in names

    def test_fastchat_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "FastChat" in names

    def test_textgen_webui_in_all_detectors(self):
        names = [d.platform_name for d in ALL_DETECTORS]
        assert "Text Generation WebUI" in names

    def test_total_platform_count(self):
        assert len(ALL_DETECTORS) == 19


class TestDetectorAttributes:
    """Test detector class attributes are properly set.
    Note: BasePlatformDetector requires a client on __init__, so we access
    class-level attributes directly rather than instantiating detectors.
    """

    def test_dify_attributes(self):
        assert DifyDetector.platform_name == "Dify"
        assert len(DifyDetector.default_ports) > 0
        assert len(DifyDetector.probe_paths) > 0

    def test_langflow_attributes(self):
        assert LangflowDetector.platform_name == "Langflow"
        assert 7860 in LangflowDetector.default_ports

    def test_anythingllm_attributes(self):
        assert AnythingLLMDetector.platform_name == "AnythingLLM"
        assert "/api/ping" in AnythingLLMDetector.probe_paths

    def test_localai_attributes(self):
        assert LocalAIDetector.platform_name == "LocalAI"
        assert "/v1/models" in LocalAIDetector.probe_paths

    def test_openrouter_attributes(self):
        assert OpenRouterDetector.platform_name == "OpenRouter"

    def test_crewai_attributes(self):
        assert CrewAIDetector.platform_name == "CrewAI"

    def test_autogen_attributes(self):
        assert AutoGenDetector.platform_name == "AutoGen"

    def test_langgraph_attributes(self):
        assert LangGraphDetector.platform_name == "LangGraph"
        assert "/ok" in LangGraphDetector.probe_paths

    def test_openhands_attributes(self):
        assert OpenHandsDetector.platform_name == "OpenHands"

    def test_fastchat_attributes(self):
        assert FastChatDetector.platform_name == "FastChat"
        assert "/worker_get_status" in FastChatDetector.probe_paths

    def test_textgen_webui_attributes(self):
        assert TextGenWebUIDetector.platform_name == "Text Generation WebUI"
        assert 7860 in TextGenWebUIDetector.default_ports

    def test_all_detectors_have_platform_name(self):
        for detector_cls in ALL_DETECTORS:
            assert detector_cls.platform_name, f"{detector_cls.__name__} missing platform_name"

    def test_all_detectors_have_default_ports(self):
        for detector_cls in ALL_DETECTORS:
            assert detector_cls.default_ports, f"{detector_cls.platform_name} has no default_ports"

    def test_all_detectors_have_probe_paths(self):
        for detector_cls in ALL_DETECTORS:
            assert detector_cls.probe_paths, f"{detector_cls.platform_name} has no probe_paths"

    def test_all_detectors_have_service_type(self):
        for detector_cls in ALL_DETECTORS:
            assert detector_cls.service_type is not None

    def test_no_duplicate_platform_names(self):
        names = [detector_cls.platform_name for detector_cls in ALL_DETECTORS]
        assert len(names) == len(set(names)), "Duplicate platform names in ALL_DETECTORS"
