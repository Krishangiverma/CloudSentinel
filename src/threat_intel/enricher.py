"""
CloudSentinel Threat Intelligence Enricher.

Provides deterministic local context for extracted IOCs
and optionally enriches them through a threat-intelligence
provider manager.
"""

import ipaddress

from src.threat_intel.ioc_model import IOC


def classify_ip(ip):
    """
    Classify an IP address.
    """

    try:
        address = ipaddress.ip_address(
            str(ip).strip()
        )
    except ValueError:
        return "invalid"

    if address.is_loopback:
        return "loopback"

    if address.is_private:
        return "private"

    if address.is_reserved:
        return "reserved"

    if address.is_unspecified:
        return "unspecified"

    if address.is_global:
        return "public"

    return "other"


def enrich_ioc(
    ioc_type,
    value,
    provider_manager=None,
    provider_name=None,
):
    """
    Enrich one IOC.

    Local enrichment is always performed.

    If a provider manager is supplied, the external
    provider result is merged into the normalized
    enrichment fields.
    """

    ioc_type = str(
        ioc_type
    ).strip().lower()

    value = str(
        value
    ).strip()

    result = {
        "ioc_type": ioc_type,
        "value": value,

        "source": "local",

        "verdict": "unknown",

        "reputation": None,

        "confidence": 0,

        "first_seen": None,

        "last_seen": None,

        "context": "unknown",
    }

    if ioc_type == "ip":

        context = classify_ip(value)

        result["context"] = context

        if context in {
            "private",
            "loopback",
            "reserved",
            "unspecified",
        }:
            result["verdict"] = "non_public"

    elif ioc_type == "domain":
        result["context"] = "domain"

    elif ioc_type == "url":
        result["context"] = "url"

    elif ioc_type in {
        "md5",
        "sha1",
        "sha256",
    }:
        result["context"] = "file_hash"

    else:
        result["context"] = "unknown_type"

    if provider_manager is None:
        return result

    ioc = IOC(
        ioc_type,
        value,
    )

    provider_result = provider_manager.lookup(
        ioc,
        provider_name=provider_name,
    )

    if provider_result.get(
        "status"
    ) != "success":
        result["provider_status"] = (
            provider_result.get(
                "status"
            )
        )

        return result

    result["source"] = provider_result.get(
        "source",
        provider_result.get(
            "provider",
            "unknown",
        ),
    )

    result["reputation"] = (
        provider_result.get(
            "reputation"
        )
    )

    result["confidence"] = (
        provider_result.get(
            "confidence"
        )
    )

    result["first_seen"] = (
        provider_result.get(
            "first_seen"
        )
    )

    result["last_seen"] = (
        provider_result.get(
            "last_seen"
        )
    )

    result["provider_status"] = "success"

    return result


def enrich_iocs(
    iocs,
    provider_manager=None,
    provider_name=None,
):
    """
    Enrich a collection of extracted IOCs.
    """

    enriched = []

    for ip in iocs.get(
        "ips",
        [],
    ):
        enriched.append(
            enrich_ioc(
                "ip",
                ip,
                provider_manager,
                provider_name,
            )
        )

    for domain in iocs.get(
        "domains",
        [],
    ):
        enriched.append(
            enrich_ioc(
                "domain",
                domain,
                provider_manager,
                provider_name,
            )
        )

    for url in iocs.get(
        "urls",
        [],
    ):
        enriched.append(
            enrich_ioc(
                "url",
                url,
                provider_manager,
                provider_name,
            )
        )

    hashes = iocs.get(
        "hashes",
        {},
    )

    for hash_type in (
        "md5",
        "sha1",
        "sha256",
    ):
        for value in hashes.get(
            hash_type,
            [],
        ):
            enriched.append(
                enrich_ioc(
                    hash_type,
                    value,
                    provider_manager,
                    provider_name,
                )
            )

    return {
        "total": len(enriched),
        "items": enriched,
    }


def enrich_event_iocs(
    event,
    ioc_extractor,
    provider_manager=None,
    provider_name=None,
):
    """
    Extract and enrich IOCs from an event.

    The original event is not modified.
    """

    iocs = ioc_extractor.extract_iocs(
        event
    )

    threat_intel = enrich_iocs(
        iocs,
        provider_manager=provider_manager,
        provider_name=provider_name,
    )

    return {
        "iocs": iocs,
        "threat_intel": threat_intel,
    }
