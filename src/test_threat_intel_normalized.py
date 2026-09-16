from src.threat_intel.ioc_model import IOC
from src.threat_intel.normalized import ThreatIntelObject


def test_ip_provider_result_becomes_normalized_indicator():
    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    result = {
        "status": "success",
        "provider": "otx",
        "ioc": ioc.to_dict(),
        "reputation": 75,
        "confidence": 90,
        "first_seen": "2026-09-01T10:00:00Z",
        "last_seen": "2026-09-10T10:00:00Z",
        "source": "AlienVault OTX",
        "cached": False,
    }

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        result,
        retrieved_at="2026-09-28T00:00:00Z",
    )

    assert obj.object_type == "indicator"
    assert obj.spec_version == "2.1"
    assert obj.object_id.startswith(
        "indicator--"
    )

    assert obj.ioc_type == "ip"
    assert obj.value == "8.8.8.8"

    assert obj.pattern == (
        "[ipv4-addr:value = '8.8.8.8']"
    )
    assert obj.pattern_type == "stix"

    assert obj.provider == "otx"
    assert obj.source == "AlienVault OTX"

    assert obj.reputation == 75
    assert obj.confidence == 90

    assert obj.first_seen == (
        "2026-09-01T10:00:00Z"
    )
    assert obj.last_seen == (
        "2026-09-10T10:00:00Z"
    )

    assert obj.valid_from == (
        "2026-09-01T10:00:00Z"
    )


def test_same_ioc_produces_deterministic_object_id():
    ioc = IOC(
        "domain",
        "example.com",
    )

    result = {
        "status": "success",
        "provider": "otx",
        "source": "AlienVault OTX",
        "confidence": 50,
    }

    first = ThreatIntelObject.from_provider_result(
        ioc,
        result,
        retrieved_at="2026-09-28T00:00:00Z",
    )

    second = ThreatIntelObject.from_provider_result(
        ioc,
        result,
        retrieved_at="2026-09-29T00:00:00Z",
    )

    assert first.object_id == second.object_id


def test_domain_pattern_is_normalized():
    ioc = IOC(
        "domain",
        "malicious.example",
    )

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        {
            "status": "success",
            "provider": "otx",
        },
        retrieved_at="2026-09-28T00:00:00Z",
    )

    assert obj.pattern == (
        "[domain-name:value = 'malicious.example']"
    )


def test_url_pattern_is_normalized():
    ioc = IOC(
        "url",
        "https://example.com/a",
    )

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        {
            "status": "success",
            "provider": "otx",
        },
        retrieved_at="2026-09-28T00:00:00Z",
    )

    assert obj.pattern == (
        "[url:value = 'https://example.com/a']"
    )


def test_hash_pattern_is_normalized():
    ioc = IOC(
        "sha256",
        "a" * 64,
    )

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        {
            "status": "success",
            "provider": "otx",
        },
        retrieved_at="2026-09-28T00:00:00Z",
    )

    assert obj.pattern == (
        "[file:hashes.SHA-256 = '"
        + ("a" * 64)
        + "']"
    )


def test_missing_first_seen_uses_retrieved_at():
    ioc = IOC(
        "ip",
        "1.2.3.4",
    )

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        {
            "status": "success",
            "provider": "otx",
        },
        retrieved_at="2026-09-28T12:00:00Z",
    )

    assert obj.first_seen is None
    assert obj.last_seen is None

    assert obj.valid_from == (
        "2026-09-28T12:00:00Z"
    )


def test_provider_specific_data_is_preserved():
    ioc = IOC(
        "ip",
        "8.8.8.8",
    )

    result = {
        "status": "success",
        "provider": "otx",
        "source": "AlienVault OTX",
        "reputation": 40,
        "pulse_count": 7,
        "custom_provider_field": "preserve-me",
    }

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        result,
        retrieved_at="2026-09-28T00:00:00Z",
    )

    assert obj.raw["pulse_count"] == 7
    assert (
        obj.raw["custom_provider_field"]
        == "preserve-me"
    )


def test_stix_like_serialization_contains_core_fields():
    ioc = IOC(
        "ip",
        "10.10.10.10",
    )

    obj = ThreatIntelObject.from_provider_result(
        ioc,
        {
            "status": "success",
            "provider": "otx",
            "confidence": 80,
        },
        retrieved_at="2026-09-28T00:00:00Z",
    )

    data = obj.to_stix_like_dict()

    assert data["type"] == "indicator"
    assert data["spec_version"] == "2.1"
    assert data["id"] == obj.object_id
    assert data["pattern"] == (
        "[ipv4-addr:value = '10.10.10.10']"
    )
    assert data["pattern_type"] == "stix"
    assert data["valid_from"] == (
        "2026-09-28T00:00:00Z"
    )

    assert data["x_cloudsentinel"]["ioc_type"] == "ip"
    assert data["x_cloudsentinel"]["confidence"] == 80
