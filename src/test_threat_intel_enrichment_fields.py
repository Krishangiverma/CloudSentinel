"""
Day 56 tests for normalized IOC enrichment fields.
"""

from src.threat_intel.enricher import (
    enrich_ioc,
    enrich_iocs,
)
from src.threat_intel.ioc_model import IOC
from src.threat_intel.provider_manager import (
    ThreatIntelProviderManager,
)
from src.threat_intel.providers.base import (
    ThreatIntelProvider,
)


REQUIRED_FIELDS = {
    "ioc_type",
    "value",
    "source",
    "verdict",
    "reputation",
    "confidence",
    "first_seen",
    "last_seen",
    "context",
}


class EnrichmentProvider(
    ThreatIntelProvider
):

    @property
    def name(self):
        return "test-provider"

    def lookup(self, ioc):
        return {
            "status": "success",
            "provider": self.name,
            "source": self.name,
            "ioc": ioc.to_dict(),
            "reputation": 85,
            "confidence": 92,
            "first_seen": "2026-01-10T10:00:00",
            "last_seen": "2026-09-20T15:30:00",
        }


def test_local_ip_enrichment_contains_all_fields():
    result = enrich_ioc(
        "ip",
        "8.8.8.8",
    )

    assert REQUIRED_FIELDS.issubset(
        result.keys()
    )

    assert result["ioc_type"] == "ip"
    assert result["value"] == "8.8.8.8"
    assert result["source"] == "local"
    assert result["reputation"] is None
    assert result["confidence"] == 0
    assert result["first_seen"] is None
    assert result["last_seen"] is None


def test_local_loopback_enrichment_preserves_context():
    result = enrich_ioc(
        "ip",
        "127.0.0.1",
    )

    assert result["context"] == "loopback"
    assert result["verdict"] == "non_public"


def test_local_domain_enrichment_contains_fields():
    result = enrich_ioc(
        "domain",
        "example.com",
    )

    assert REQUIRED_FIELDS.issubset(
        result.keys()
    )

    assert result["context"] == "domain"
    assert result["source"] == "local"


def test_local_url_enrichment_contains_fields():
    result = enrich_ioc(
        "url",
        "https://example.com/login",
    )

    assert REQUIRED_FIELDS.issubset(
        result.keys()
    )

    assert result["context"] == "url"


def test_local_hash_enrichment_contains_fields():
    result = enrich_ioc(
        "sha256",
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855",
    )

    assert REQUIRED_FIELDS.issubset(
        result.keys()
    )

    assert result["context"] == "file_hash"


def test_provider_enrichment_populates_fields():
    provider = EnrichmentProvider()

    manager = ThreatIntelProviderManager(
        providers=[provider]
    )

    result = enrich_ioc(
        "ip",
        "8.8.8.8",
        provider_manager=manager,
        provider_name="test-provider",
    )

    assert REQUIRED_FIELDS.issubset(
        result.keys()
    )

    assert result["source"] == "test-provider"
    assert result["reputation"] == 85
    assert result["confidence"] == 92
    assert result["first_seen"] == (
        "2026-01-10T10:00:00"
    )
    assert result["last_seen"] == (
        "2026-09-20T15:30:00"
    )
    assert result["provider_status"] == "success"


def test_provider_fields_are_preserved_for_urls():
    provider = EnrichmentProvider()

    manager = ThreatIntelProviderManager(
        providers=[provider]
    )

    result = enrich_ioc(
        "url",
        "https://example.com/malware",
        provider_manager=manager,
        provider_name="test-provider",
    )

    assert result["context"] == "url"
    assert result["source"] == "test-provider"
    assert result["reputation"] == 85
    assert result["confidence"] == 92


def test_provider_failure_preserves_local_enrichment():
    provider = EnrichmentProvider()

    manager = ThreatIntelProviderManager(
        providers=[provider]
    )

    result = enrich_ioc(
        "domain",
        "example.com",
        provider_manager=manager,
        provider_name="missing-provider",
    )

    assert result["context"] == "domain"
    assert result["source"] == "local"
    assert result["reputation"] is None
    assert result["first_seen"] is None
    assert result["last_seen"] is None
    assert result["provider_status"] == (
        "provider_not_found"
    )


def test_collection_enrichment_includes_urls():
    iocs = {
        "ips": ["8.8.8.8"],
        "domains": ["example.com"],
        "urls": [
            "https://example.com/test"
        ],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }

    result = enrich_iocs(iocs)

    assert result["total"] == 3
    assert len(result["items"]) == 3

    types = {
        item["ioc_type"]
        for item in result["items"]
    }

    assert types == {
        "ip",
        "domain",
        "url",
    }
