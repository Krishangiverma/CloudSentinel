"""
Day 55 tests for the AlienVault OTX provider.
"""

import json
from io import BytesIO

import pytest

from src.threat_intel.ioc_model import IOC
from src.threat_intel.providers.otx import (
    OTXProvider,
)


class FakeResponse:

    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        return False

    def read(self):
        return json.dumps(
            self.payload
        ).encode("utf-8")


def make_opener(payload):
    captured = {}

    def opener(
        request,
        timeout=None,
    ):
        captured["url"] = request.full_url
        captured["headers"] = dict(
            request.header_items()
        )
        captured["timeout"] = timeout

        return FakeResponse(
            payload
        )

    opener.captured = captured

    return opener


def test_otx_provider_name():
    provider = OTXProvider(
        api_key="test-key"
    )

    assert provider.name == "otx"


def test_otx_reads_api_key_from_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "OTX_API_KEY",
        "environment-key",
    )

    provider = OTXProvider()

    assert provider.api_key == "environment-key"


def test_otx_requires_api_key():
    provider = OTXProvider(
        api_key=""
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    with pytest.raises(
        RuntimeError,
        match="OTX_API_KEY",
    ):
        provider.lookup(ioc)


def test_otx_ip_lookup():
    payload = {
        "pulse_info": {
            "count": 2,
            "pulses": [
                {"name": "Test Pulse One"},
                {"name": "Test Pulse Two"},
            ],
        },
        "reputation": 0,
    }

    opener = make_opener(
        payload
    )

    provider = OTXProvider(
        api_key="test-key",
        opener=opener,
    )

    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    result = provider.lookup(ioc)

    assert result["status"] == "success"
    assert result["provider"] == "otx"
    assert result["found"] is True
    assert result["pulse_count"] == 2
    assert result["reputation"] == 0
    assert result["pulse_names"] == [
        "Test Pulse One",
        "Test Pulse Two",
    ]

    assert (
        "/indicators/IPv4/8.8.8.8/general"
        in opener.captured["url"]
    )

    assert (
        opener.captured["headers"][
            "X-otx-api-key"
        ]
        == "test-key"
    )


def test_otx_domain_lookup():
    opener = make_opener(
        {
            "pulse_info": {
                "count": 0,
                "pulses": [],
            }
        }
    )

    provider = OTXProvider(
        api_key="test-key",
        opener=opener,
    )

    result = provider.lookup(
        IOC(
            "domain",
            "example.com",
        )
    )

    assert result["status"] == "success"
    assert result["found"] is False
    assert result["pulse_count"] == 0

    assert (
        "/indicators/domain/example.com/general"
        in opener.captured["url"]
    )


def test_otx_url_lookup():
    opener = make_opener(
        {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {"name": "URL Test"},
                ],
            }
        }
    )

    provider = OTXProvider(
        api_key="test-key",
        opener=opener,
    )

    result = provider.lookup(
        IOC(
            "url",
            "https://example.com/login?id=10",
        )
    )

    assert result["status"] == "success"
    assert result["found"] is True
    assert result["pulse_count"] == 1

    assert (
        "/indicators/url/"
        in opener.captured["url"]
    )

    assert (
        "%3A%2F%2F"
        in opener.captured["url"]
    )


@pytest.mark.parametrize(
    "ioc_type",
    [
        "md5",
        "sha1",
        "sha256",
    ],
)
def test_otx_hash_lookup(
    ioc_type,
):
    opener = make_opener(
        {
            "pulse_info": {
                "count": 0,
                "pulses": [],
            }
        }
    )

    provider = OTXProvider(
        api_key="test-key",
        opener=opener,
    )

    value = {
        "md5": (
            "d41d8cd98f00b204e9800998ecf8427e"
        ),
        "sha1": (
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ),
        "sha256": (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
    }[ioc_type]

    result = provider.lookup(
        IOC(
            ioc_type,
            value,
        )
    )

    assert result["status"] == "success"

    assert (
        "/indicators/file/"
        in opener.captured["url"]
    )


def test_otx_timeout_configuration():
    provider = OTXProvider(
        api_key="test-key",
        request_timeout=7,
    )

    assert provider.request_timeout == 7


def test_otx_rejects_invalid_ioc():
    provider = OTXProvider(
        api_key="test-key"
    )

    with pytest.raises(TypeError):
        provider.lookup(
            "8.8.8.8"
        )
