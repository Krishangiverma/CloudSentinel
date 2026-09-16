"""
Day 54 tests for the CloudSentinel threat-intelligence
provider abstraction, caching and timeout handling.
"""

import time

import pytest

from src.threat_intel.cache import ThreatIntelCache
from src.threat_intel.ioc_model import IOC
from src.threat_intel.provider_manager import (
    ThreatIntelProviderManager,
)
from src.threat_intel.providers.base import (
    ThreatIntelProvider,
)


class FakeProvider(ThreatIntelProvider):

    def __init__(self):
        self.calls = 0

    @property
    def name(self):
        return "fake"

    def lookup(self, ioc):
        self.calls += 1

        return {
            "status": "success",
            "provider": self.name,
            "ioc": ioc.to_dict(),
            "verdict": "unknown",
        }


class SlowProvider(ThreatIntelProvider):

    @property
    def name(self):
        return "slow"

    def lookup(self, ioc):
        time.sleep(0.2)

        return {
            "status": "success",
            "provider": self.name,
            "ioc": ioc.to_dict(),
        }


def test_provider_is_abstract():
    with pytest.raises(TypeError):
        ThreatIntelProvider()


def test_provider_registration():
    provider = FakeProvider()

    manager = ThreatIntelProviderManager(
        providers=[provider]
    )

    assert "fake" in manager.providers


def test_provider_lookup():
    provider = FakeProvider()

    manager = ThreatIntelProviderManager(
        providers=[provider]
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    result = manager.lookup(ioc)

    assert result["status"] == "success"
    assert result["provider"] == "fake"
    assert result["ioc"]["ioc_type"] == "ip"
    assert result["ioc"]["value"] == "8.8.8.8"
    assert result["cached"] is False

    assert provider.calls == 1


def test_provider_result_is_cached():
    provider = FakeProvider()

    manager = ThreatIntelProviderManager(
        providers=[provider],
        cache=ThreatIntelCache(
            ttl_seconds=60
        ),
    )

    ioc = IOC(
        "domain",
        "example.com",
    )

    first = manager.lookup(ioc)
    second = manager.lookup(ioc)

    assert first["cached"] is False
    assert second["cached"] is True

    assert provider.calls == 1


def test_cache_expires():
    current_time = [100.0]

    cache = ThreatIntelCache(
        ttl_seconds=10,
        time_function=lambda: current_time[0],
    )

    cache.set(
        "test",
        {"value": 123},
    )

    assert cache.get("test") == {
        "value": 123
    }

    current_time[0] = 111.0

    assert cache.get("test") is None


def test_cache_clear():
    cache = ThreatIntelCache(
        ttl_seconds=60
    )

    cache.set(
        "test",
        "value",
    )

    assert len(cache) == 1

    cache.clear()

    assert len(cache) == 0
    assert cache.get("test") is None


def test_provider_timeout():
    manager = ThreatIntelProviderManager(
        providers=[SlowProvider()],
        timeout_seconds=0.05,
    )

    ioc = IOC(
        "url",
        "https://example.com/test",
    )

    result = manager.lookup(ioc)

    assert result["status"] == "timeout"
    assert result["provider"] == "slow"
    assert result["timeout_seconds"] == 0.05


def test_missing_provider():
    manager = ThreatIntelProviderManager(
        providers=[FakeProvider()]
    )

    ioc = IOC(
        "ip",
        "1.1.1.1",
    )

    result = manager.lookup(
        ioc,
        provider_name="missing",
    )

    assert result["status"] == "provider_not_found"
    assert result["provider"] == "missing"


def test_no_provider():
    manager = ThreatIntelProviderManager()

    ioc = IOC(
        "ip",
        "1.1.1.1",
    )

    result = manager.lookup(ioc)

    assert result["status"] == "no_provider"


def test_invalid_ioc_argument():
    manager = ThreatIntelProviderManager(
        providers=[FakeProvider()]
    )

    with pytest.raises(TypeError):
        manager.lookup(
            "8.8.8.8"
        )
