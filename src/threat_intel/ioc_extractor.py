"""
CloudSentinel IOC Extractor.

Extracts common Indicators of Compromise (IOCs) from
security-event messages.

Supported IOC types:

    IPv4
    Domain
    MD5
    SHA1
    SHA256

This module is intentionally deterministic and offline.
It does not contact external threat-intelligence services.
"""

import ipaddress
import re


# ============================================================
# REGULAR EXPRESSIONS
# ============================================================

IPV4_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


MD5_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
)


SHA1_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{40}\b"
)


SHA256_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{64}\b"
)


DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
    r"[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)


# ============================================================
# IP EXTRACTION
# ============================================================

def extract_ipv4(text):
    """
    Extract valid IPv4 addresses from text.

    Invalid addresses such as 999.999.999.999 are ignored.
    """

    if not text:
        return []

    matches = IPV4_PATTERN.findall(
        str(text)
    )

    results = []

    for value in matches:

        try:
            ipaddress.IPv4Address(
                value
            )

            if value not in results:
                results.append(value)

        except ValueError:
            continue

    return results


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domains(text):
    """
    Extract domain names from text.

    IPv4 addresses are not considered domains.
    """

    if not text:
        return []

    matches = DOMAIN_PATTERN.findall(
        str(text)
    )

    results = []

    for domain in matches:

        domain = domain.lower()

        if domain not in results:
            results.append(domain)

    return results


# ============================================================
# HASH EXTRACTION
# ============================================================

def extract_hashes(text):
    """
    Extract MD5, SHA1 and SHA256 hashes.

    Returns:
        {
            "md5": [...],
            "sha1": [...],
            "sha256": [...]
        }
    """

    if not text:
        return {
            "md5": [],
            "sha1": [],
            "sha256": [],
        }

    value = str(text)

    sha256 = list(
        dict.fromkeys(
            match.lower()
            for match in SHA256_PATTERN.findall(
                value
            )
        )
    )

    sha1 = list(
        dict.fromkeys(
            match.lower()
            for match in SHA1_PATTERN.findall(
                value
            )
        )
    )

    md5 = list(
        dict.fromkeys(
            match.lower()
            for match in MD5_PATTERN.findall(
                value
            )
        )
    )

    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
    }


# ============================================================
# EVENT TEXT
# ============================================================

def _get_event_text(event):
    """
    Extract searchable text from a CloudSentinel event.

    Supports:

        SecurityEvent objects
        dictionaries
        plain strings
    """

    if event is None:
        return ""

    if isinstance(event, str):
        return event

    if isinstance(event, dict):

        return str(
            event.get(
                "message",
                "",
            )
        )

    message = getattr(
        event,
        "message",
        "",
    )

    return str(message)


# ============================================================
# IOC EXTRACTION
# ============================================================

def extract_iocs(event):
    """
    Extract all supported IOCs from a security event.

    Returns:

        {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": []
            }
        }
    """

    text = _get_event_text(
        event
    )

    result = {
        "ips": extract_ipv4(text),
        "domains": extract_domains(text),
        "hashes": extract_hashes(text),
    }

    # --------------------------------------------------------
    # Include canonical event IP when available.
    # --------------------------------------------------------

    if isinstance(event, dict):

        event_ip = event.get(
            "ip_address"
        )

    else:

        event_ip = getattr(
            event,
            "ip_address",
            None,
        )

    if event_ip:

        event_ip = str(
            event_ip
        ).strip()

        try:

            ipaddress.IPv4Address(
                event_ip
            )

            if event_ip not in result["ips"]:
                result["ips"].insert(
                    0,
                    event_ip,
                )

        except ValueError:
            pass

    return result
