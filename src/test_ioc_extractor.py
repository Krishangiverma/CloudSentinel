"""
Day 40 tests for the CloudSentinel IOC extractor.
"""

from src.threat_intel.ioc_extractor import (
    extract_ipv4,
    extract_domains,
    extract_hashes,
    extract_iocs,
)


def test_extract_ipv4_addresses():
    text = (
        "Failed login from 192.168.1.50 "
        "and 10.0.0.5"
    )

    result = extract_ipv4(text)

    assert result == [
        "192.168.1.50",
        "10.0.0.5",
    ]


def test_invalid_ipv4_is_ignored():
    text = (
        "Connection from 999.999.999.999 "
        "was rejected."
    )

    result = extract_ipv4(text)

    assert result == []


def test_extract_domains():
    text = (
        "Connection attempted to "
        "malicious-example.com and "
        "cdn.example.org"
    )

    result = extract_domains(text)

    assert result == [
        "malicious-example.com",
        "cdn.example.org",
    ]


def test_extract_hashes():
    md5 = "d41d8cd98f00b204e9800998ecf8427e"

    sha1 = (
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )

    sha256 = (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )

    text = (
        f"MD5={md5} "
        f"SHA1={sha1} "
        f"SHA256={sha256}"
    )

    result = extract_hashes(text)

    assert result["md5"] == [
        md5
    ]

    assert result["sha1"] == [
        sha1
    ]

    assert result["sha256"] == [
        sha256
    ]


def test_extract_iocs_from_dictionary_event():
    event = {
        "message": (
            "Failed login from "
            "10.0.0.50 contacting evil.example.com"
        ),
        "ip_address": "10.0.0.50",
    }

    result = extract_iocs(event)

    assert result["ips"] == [
        "10.0.0.50"
    ]

    assert result["domains"] == [
        "evil.example.com"
    ]


def test_extract_iocs_from_security_event():
    class Event:
        message = (
            "Malware contacted "
            "bad.example.net from 8.8.8.8"
        )

        ip_address = "8.8.8.8"

    result = extract_iocs(
        Event()
    )

    assert result["ips"] == [
        "8.8.8.8"
    ]

    assert result["domains"] == [
        "bad.example.net"
    ]


def test_duplicate_iocs_are_removed():
    text = (
        "Attack from 10.0.0.5 "
        "then again from 10.0.0.5"
    )

    result = extract_iocs(
        {
            "message": text
        }
    )

    assert result["ips"] == [
        "10.0.0.5"
    ]


def test_empty_event_returns_empty_iocs():
    result = extract_iocs(
        {
            "message": ""
        }
    )

    assert result == {
        "ips": [],
        "domains": [],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }
