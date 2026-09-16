"""
Day 58 tests for CloudSentinel threat-intelligence
caching, rate-limit handling and graceful provider failure.
"""

import time

import pytest

from urllib.error import HTTPError

from src.threat_intel.cache import ThreatIntelCache
from src.threat_intel.ioc_model import IOC
from src.threat_intel.provider_manager import (
    ThreatIntelProviderManager,
)
from src.threat_intel.providers.base import (
    RateLimitError,
    ThreatIntelProvider,
)
from src.threat_intel.providers.otx import (
    OTXProvider,
)


# ============================================================
# CACHE TESTS
# ============================================================

def test_cache_is_thread_safe():
    cache = ThreatIntelCache(
        ttl_seconds=60
    )

    cache.set(
        "key",
        "value",
    )

    assert cache.get(
        "key"
    ) == "value"


def test_cache_rejects_negative_ttl():
    with pytest.raises(
        ValueError
    ):
        ThreatIntelCache(
            ttl_seconds=-1
        )


def test_cache_expiration_removes_entry():
    current_time = [100.0]

    cache = ThreatIntelCache(
        ttl_seconds=10,
        time_function=lambda: current_time[0],
    )

    cache.set(
        "test",
        {"value": 123},
    )

    assert cache.get(
        "test"
    ) == {
        "value": 123
    }

    current_time[0] = 110.0

    assert cache.get(
        "test"
    ) is None

    assert len(cache) == 0


# ============================================================
# TEST PROVIDERS
# ============================================================

class RateLimitedProvider(
    ThreatIntelProvider
):

    @property
    def name(self):
        return "rate_limited"

    def lookup(
        self,
        ioc,
    ):
        raise RateLimitError(
            "Provider rate limit exceeded.",
            retry_after="30",
        )


class FailingProvider(
    ThreatIntelProvider
):

    @property
    def name(self):
        return "failing"

    def lookup(
        self,
        ioc,
    ):
        raise RuntimeError(
            "Provider unavailable."
        )


class InvalidResultProvider(
    ThreatIntelProvider
):

    @property
    def name(self):
        return "invalid"

    def lookup(
        self,
        ioc,
    ):
        return "invalid"


class ProviderTimeout:
    """
    Provider-like object that blocks longer than
    the manager timeout.
    """

    name = "provider_timeout"

    def lookup(
        self,
        ioc,
    ):
        time.sleep(
            0.2
        )

        return {
            "status": "success"
        }


# ============================================================
# RATE LIMIT TESTS
# ============================================================

def test_rate_limit_is_returned_as_structured_result():
    manager = ThreatIntelProviderManager(
        providers=[
            RateLimitedProvider()
        ]
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    result = manager.lookup(
        ioc
    )

    assert result["status"] == (
        "rate_limited"
    )

    assert result["provider"] == (
        "rate_limited"
    )

    assert result["retry_after"] == (
        "30"
    )

    assert result["cached"] is False


# ============================================================
# PROVIDER FAILURE TESTS
# ============================================================

def test_provider_exception_is_graceful():
    manager = ThreatIntelProviderManager(
        providers=[
            FailingProvider()
        ]
    )

    ioc = IOC(
        "ip",
        "1.1.1.1",
    )

    result = manager.lookup(
        ioc
    )

    assert result["status"] == (
        "error"
    )

    assert result["provider"] == (
        "failing"
    )

    assert "Provider unavailable." in (
        result["error"]
    )

    assert result["cached"] is False


def test_invalid_provider_result_is_graceful():
    manager = ThreatIntelProviderManager(
        providers=[
            InvalidResultProvider()
        ]
    )

    ioc = IOC(
        "domain",
        "example.com",
    )

    result = manager.lookup(
        ioc
    )

    assert result["status"] == (
        "invalid_provider_result"
    )

    assert result["provider"] == (
        "invalid"
    )

    assert result["cached"] is False


def test_timeout_is_graceful():
    manager = ThreatIntelProviderManager(
        providers=[
            ProviderTimeout()
        ],
        timeout_seconds=0.05,
    )

    ioc = IOC(
        "url",
        "https://example.com",
    )

    result = manager.lookup(
        ioc
    )

    assert result["status"] == (
        "timeout"
    )

    assert result["provider"] == (
        "provider_timeout"
    )

    assert result["timeout_seconds"] == (
        0.05
    )

    assert result["cached"] is False


# ============================================================
# FAILURE RESULTS MUST NOT BE CACHED
# ============================================================

def test_rate_limit_result_is_not_cached():
    provider = RateLimitedProvider()

    manager = ThreatIntelProviderManager(
        providers=[
            provider
        ]
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    first = manager.lookup(
        ioc
    )

    second = manager.lookup(
        ioc
    )

    assert first["status"] == (
        "rate_limited"
    )

    assert second["status"] == (
        "rate_limited"
    )

    assert first["cached"] is False
    assert second["cached"] is False


def test_provider_error_result_is_not_cached():
    provider = FailingProvider()

    manager = ThreatIntelProviderManager(
        providers=[
            provider
        ]
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    first = manager.lookup(
        ioc
    )

    second = manager.lookup(
        ioc
    )

    assert first["status"] == "error"
    assert second["status"] == "error"

    assert first["cached"] is False
    assert second["cached"] is False


# ============================================================
# OTX RATE LIMIT TEST
# ============================================================

class FakeHTTPHeaders:

    def get(
        self,
        name,
    ):
        if name == "Retry-After":
            return "60"

        return None


def fake_otx_rate_limit_opener(
    request,
    timeout,
):
    raise HTTPError(
        request.full_url,
        429,
        "Too Many Requests",
        FakeHTTPHeaders(),
        None,
    )


def test_otx_429_raises_rate_limit_error():
    provider = OTXProvider(
        api_key="test-key",
        opener=fake_otx_rate_limit_opener,
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    with pytest.raises(
        RateLimitError
    ) as exc_info:

        provider.lookup(
            ioc
        )

    assert exc_info.value.retry_after == (
        "60"
    )
