"""Tests for the discovery engine."""

import pytest
from aasm.modules.discovery.engine import expand_target


def test_expand_single_ip():
    hosts = expand_target("192.168.1.1")
    assert hosts == ["192.168.1.1"]


def test_expand_cidr_24():
    hosts = expand_target("192.168.1.0/30")
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts
    assert len(hosts) == 2


def test_expand_range():
    hosts = expand_target("192.168.1.1-5")
    assert len(hosts) == 5
    assert "192.168.1.1" in hosts
    assert "192.168.1.5" in hosts


def test_expand_hostname():
    hosts = expand_target("myserver.local")
    assert hosts == ["myserver.local"]


def test_expand_cidr_32():
    hosts = expand_target("10.0.0.1/32")
    assert len(hosts) >= 1
