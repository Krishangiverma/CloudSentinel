"""
Day 40 tests for CloudSentinel threat-intelligence enrichment.
"""

from src.threat_intel.enricher import (
    classify_ip,
    enrich_ioc,
    enrich_iocs,
)


def test_private_ip_classification():
    assert classify_ip(
        "192.168.1.10"
    ) == "private"


def test_loopback_ip_classification():
    assert classify_ip(
        "127.0.0.1"
    ) == "loopback"


def test_public_ip_classification():
    assert classify_ip(
        "8.8.8.8"
    ) == "public"


def test_invalid_ip_classification():
    assert classify_ip(
        "999.999.999.999"
    ) == "invalid"


def test_ip_enrichment():
    result = enrich_ioc(
        "ip",
        "192.168.1.10",
    )

    assert result["ioc_type"] == "ip"
    assert result["value"] == "192.168.1.10"
    assert result["source"] == "local"
    assert result["context"] == "private"
    assert result["verdict"] == "non_public"
    assert result["confidence"] == 0


def test_domain_enrichment():
    result = enrich_ioc(
        "domain",
        "example.com",
    )

    assert result["ioc_type"] == "domain"
    assert result["value"] == "example.com"
    assert result["context"] == "domain"
    assert result["verdict"] == "unknown"


def test_hash_enrichment():
    result = enrich_ioc(
        "sha256",
        "a" * 64,
    )

    assert result["ioc_type"] == "sha256"
    assert result["context"] == "file_hash"
    assert result["verdict"] == "unknown"


def test_enrich_ioc_collection():
    iocs = {
        "ips": [
            "10.0.0.5",
            "8.8.8.8",
        ],
        "domains": [
            "example.com",
        ],
        "hashes": {
            "md5": [
                "d41d8cd98f00b204e9800998ecf8427e"
            ],
            "sha1": [],
            "sha256": [],
        },
    }

    result = enrich_iocs(
        iocs
    )

    assert result["total"] == 4
    assert len(
        result["items"]
    ) == 4


def test_empty_ioc_collection():
    result = enrich_iocs(
        {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        }
    )

    assert result == {
        "total": 0,
        "items": [],
    }
