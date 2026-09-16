"""
Day 60 tests for IOC investigation.
"""

from src.api.ioc_investigation import (
    _event_iocs,
    _matches,
)


def test_event_iocs_flattens_ip_domain_and_hashes():

    iocs = {
        "ips": ["8.8.8.8"],
        "domains": ["malicious.example.com"],
        "urls": [],
        "hashes": {
            "md5": [
                "d41d8cd98f00b204e9800998ecf8427e"
            ],
            "sha1": [],
            "sha256": [],
        },
    }

    result = _event_iocs(iocs)

    assert {
        "ioc_type": "ip",
        "value": "8.8.8.8",
    } in result

    assert {
        "ioc_type": "domain",
        "value": "malicious.example.com",
    } in result

    assert {
        "ioc_type": "md5",
        "value": "d41d8cd98f00b204e9800998ecf8427e",
    } in result


def test_event_iocs_supports_urls():

    result = _event_iocs({
        "ips": [],
        "domains": [],
        "urls": [
            "https://example.com/test"
        ],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    })

    assert result == [
        {
            "ioc_type": "url",
            "value": "https://example.com/test",
        }
    ]


def test_ioc_matching_is_case_insensitive():

    ioc = {
        "ioc_type": "domain",
        "value": "Malicious.Example.COM",
    }

    assert _matches(
        ioc,
        "domain",
        "malicious.example.com",
    )


def test_ioc_matching_rejects_wrong_type():

    ioc = {
        "ioc_type": "domain",
        "value": "example.com",
    }

    assert not _matches(
        ioc,
        "ip",
        "example.com",
    )


def test_ioc_matching_rejects_wrong_value():

    ioc = {
        "ioc_type": "ip",
        "value": "8.8.8.8",
    }

    assert not _matches(
        ioc,
        "ip",
        "1.1.1.1",
    )
