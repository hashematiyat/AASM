"""Tests for AASM configuration."""

import pytest
from pathlib import Path
import tempfile
import yaml

from aasm.core.config import AASMConfig, ScanProfile, reset_config


def test_default_config_loads():
    cfg = AASMConfig()
    assert cfg.discovery.timeout == 5.0
    assert cfg.discovery.concurrency == 50
    assert len(cfg.discovery.ports) > 0


def test_config_from_yaml(tmp_path):
    config_data = {
        "version": "1",
        "discovery": {"timeout": 3.0, "concurrency": 100},
        "logging": {"level": "DEBUG"},
    }
    config_file = tmp_path / "aasm.yaml"
    config_file.write_text(yaml.dump(config_data))

    cfg = AASMConfig.load(config_file)
    assert cfg.discovery.timeout == 3.0
    assert cfg.discovery.concurrency == 100
    assert cfg.logging.level == "DEBUG"


def test_config_profile_lookup():
    cfg = AASMConfig()
    cfg.profiles["quick"] = ScanProfile(
        name="quick",
        ports=[11434, 3000],
        timeout=3.0,
    )
    profile = cfg.get_profile("quick")
    assert profile is not None
    assert profile.name == "quick"
    assert 11434 in profile.ports


def test_config_profile_missing():
    cfg = AASMConfig()
    assert cfg.get_profile("nonexistent") is None


def test_config_save_and_load(tmp_path):
    cfg = AASMConfig()
    cfg.discovery.timeout = 7.5
    out = tmp_path / "test_config.yaml"
    cfg.save(out)

    loaded = AASMConfig.load(out)
    assert loaded.discovery.timeout == 7.5
