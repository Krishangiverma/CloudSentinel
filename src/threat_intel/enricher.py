"""
CloudSentinel Threat Intelligence Enricher.

Provides deterministic local context for extracted IOCs.

This module does NOT contact external threat-intelligence
providers. External providers can be added later as adapters.
"""

import ipaddress


# ============================================================
# IP CONTEXT
# ============================================================

def classify_ip(ip):
    """
    Classify an IP address using local network information.

    Returns:
        public
        private
        loopback
        reserved
        unspecified
        invalid
    """

    try:
        address = ipaddress.ip_address(
            str(ip)
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

    return "public"


# ============================================================
# SINGLE IOC ENRICHMENT
# ============================================================

def enrich_ioc(
    ioc_type,
    value,
):
    """
    Enrich one IOC with deterministic local context.

    No external network request is performed.
    """

    value = str(value).strip()

    result = {
        "ioc_type": ioc_type,
        "value": value,
        "source": "local",
        "verdict": "unknown",
        "confidence": 0,
        "context": "unknown",
    }

    if ioc_type == "ip":

        context = classify_ip(
            value
        )

        result["context"] = context

        if context in {
            "private",
            "loopback",
            "reserved",
            "unspecified",
        }:
            result["verdict"] = "non_public"

        return result

    if ioc_type == "domain":

        result["context"] = "domain"

        return result

    if ioc_type in {
        "md5",
        "sha1",
        "sha256",
    }:

        result["context"] = "file_hash"

        return result

    result["context"] = "unknown_type"

    return result


# ============================================================
# IOC COLLECTION ENRICHMENT
# ============================================================

def enrich_iocs(iocs):
    """
    Enrich a complete IOC collection returned by
    the IOC extractor.

    Expected input:

        {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": []
            }
        }

    Returns:

        {
            "total": int,
            "items": [...]
        }
    """

    if not iocs:
        return {
            "total": 0,
            "items": [],
        }

    enriched = []

    for ip in iocs.get(
        "ips",
        [],
    ):

        enriched.append(
            enrich_ioc(
                "ip",
                ip,
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
                )
            )

    return {
        "total": len(enriched),
        "items": enriched,
    }


# ============================================================
# EVENT ENRICHMENT
# ============================================================

def enrich_event_iocs(
    event,
    ioc_extractor,
):
    """
    Extract and enrich IOCs from one event.

    The original event is not modified.

    Returns:

        {
            "iocs": {...},
            "threat_intel": {...}
        }
    """

    iocs = ioc_extractor(
        event
    )

    threat_intel = enrich_iocs(
        iocs
    )

    return {
        "iocs": iocs,
        "threat_intel": threat_intel,
    }
