"""
Tests for CloudSentinel Threat Intelligence Risk Analyzer.
"""

from src.analyzers.threat_intel_risk import (
    calculate_ioc_risk,
    calculate_ioc_risk_breakdown,
    calculate_threat_intel_risk,
    analyze_threat_intel_risk,
)


def test_unknown_public_ioc_has_low_risk():
    result = calculate_ioc_risk({
        "ioc_type": "ip",
        "value": "8.8.8.8",
        "verdict": "unknown",
        "context": "public",
    })

    assert result == 5


def test_suspicious_ioc_has_medium_risk():
    result = calculate_ioc_risk({
        "ioc_type": "domain",
        "value": "suspicious.example.com",
        "verdict": "suspicious",
        "context": "domain",
    })

    assert result == 25


def test_malicious_ioc_has_high_risk():
    result = calculate_ioc_risk({
        "ioc_type": "ip",
        "value": "1.2.3.4",
        "verdict": "malicious",
        "context": "public",
    })

    assert result == 35


def test_private_ioc_has_zero_risk():
    result = calculate_ioc_risk({
        "ioc_type": "ip",
        "value": "192.168.1.10",
        "verdict": "non_public",
        "context": "private",
    })

    assert result == 0


def test_highest_ioc_score_is_used():
    result = calculate_threat_intel_risk({
        "total": 3,
        "items": [
            {
                "ioc_type": "ip",
                "value": "8.8.8.8",
                "verdict": "unknown",
                "context": "public",
            },
            {
                "ioc_type": "domain",
                "value": "example.com",
                "verdict": "suspicious",
                "context": "domain",
            },
            {
                "ioc_type": "ip",
                "value": "1.2.3.4",
                "verdict": "malicious",
                "context": "public",
            },
        ],
    })

    assert result["threat_intel_score"] == 35
    assert result["threat_intel_level"] == "HIGH"
    assert result["ioc_count"] == 3


def test_empty_threat_intel_returns_low():
    result = calculate_threat_intel_risk({})

    assert result == {
        "threat_intel_score": 0,
        "threat_intel_level": "LOW",
        "ioc_count": 0,
    }


def test_event_without_threat_intel():
    result = analyze_threat_intel_risk({
        "event_type": "SUSPICIOUS_LOGIN",
        "severity": "HIGH",
    })

    assert result == {
        "threat_intel_score": 0,
        "threat_intel_level": "LOW",
        "ioc_count": 0,
    }


def test_invalid_ioc_is_ignored():
    result = calculate_threat_intel_risk({
        "items": [
            "invalid",
            None,
            123,
        ]
    })

    assert result == {
        "threat_intel_score": 0,
        "threat_intel_level": "LOW",
        "ioc_count": 0,
    }


def test_reputation_adjustment_is_bounded():
    from src.analyzers.threat_intel_risk import (
        calculate_reputation_adjustment,
    )

    assert calculate_reputation_adjustment(
        0
    ) == 0

    assert calculate_reputation_adjustment(
        20
    ) == 5

    assert calculate_reputation_adjustment(
        40
    ) == 10

    assert calculate_reputation_adjustment(
        60
    ) == 15

    assert calculate_reputation_adjustment(
        80
    ) == 20

    assert calculate_reputation_adjustment(
        95
    ) == 25

    assert calculate_reputation_adjustment(
        500
    ) == 25


def test_invalid_reputation_has_no_adjustment():
    from src.analyzers.threat_intel_risk import (
        calculate_reputation_adjustment,
    )

    assert calculate_reputation_adjustment(
        None
    ) == 0

    assert calculate_reputation_adjustment(
        "invalid"
    ) == 0


def test_reputation_is_added_to_ioc_risk():
    result = calculate_ioc_risk_breakdown({
        "ioc_type": "ip",
        "value": "1.2.3.4",
        "verdict": "unknown",
        "context": "public",
        "reputation": 80,
    })

    assert result["verdict_bonus"] == 0
    assert result["context_bonus"] == 5
    assert result["reputation_adjustment"] == 20
    assert result["total"] == 25


def test_reputation_adjustment_is_reported():
    result = calculate_threat_intel_risk({
        "total": 1,
        "items": [{
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "verdict": "unknown",
            "context": "public",
            "reputation": 80,
        }],
    })

    assert result["threat_intel_score"] == 25
    assert result["reputation_adjustment"] == 20
    assert result["threat_intel_level"] == "MEDIUM"


def test_missing_reputation_preserves_existing_score():
    result = calculate_threat_intel_risk({
        "items": [{
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "verdict": "malicious",
            "context": "public",
        }],
    })

    assert result["threat_intel_score"] == 35
    assert result["reputation_adjustment"] == 0
