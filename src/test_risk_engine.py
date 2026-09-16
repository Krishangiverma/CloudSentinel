"""
Tests for the CloudSentinel Risk Engine.
"""

from src.analyzers.risk_engine import (
    calculate_risk_score,
    analyze_event_risk,
)


def test_original_risk_calculation_is_preserved():
    result = calculate_risk_score({
        "severity": "HIGH",
        "event_type": "BRUTE_FORCE",
    })

    assert result["risk_score"] == 80
    assert result["risk_level"] == "CRITICAL"
    assert result["threat_intel_score"] == 0


def test_low_severity_without_threat_intel():
    result = calculate_risk_score({
        "severity": "LOW",
        "event_type": "SUSPICIOUS_LOGIN",
    })

    assert result["risk_score"] == 30
    assert result["risk_level"] == "LOW"
    assert result["threat_intel_score"] == 0


def test_threat_intelligence_increases_risk():
    result = calculate_risk_score({
        "severity": "MEDIUM",
        "event_type": "SUSPICIOUS_LOGIN",
        "threat_intel": {
            "total": 1,
            "items": [{
                "ioc_type": "ip",
                "value": "1.2.3.4",
                "verdict": "malicious",
                "context": "public",
            }],
        },
    })

    assert result["threat_intel_score"] == 35
    assert result["risk_score"] == 90
    assert result["risk_level"] == "CRITICAL"


def test_risk_score_is_capped_at_100():
    result = calculate_risk_score({
        "severity": "CRITICAL",
        "event_type": "MALWARE",
        "threat_intel": {
            "total": 1,
            "items": [{
                "ioc_type": "ip",
                "value": "1.2.3.4",
                "verdict": "malicious",
                "context": "public",
            }],
        },
    })

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"


def test_private_ioc_does_not_add_threat_risk():
    result = calculate_risk_score({
        "severity": "LOW",
        "event_type": "SUSPICIOUS_LOGIN",
        "threat_intel": {
            "total": 1,
            "items": [{
                "ioc_type": "ip",
                "value": "192.168.1.10",
                "verdict": "non_public",
                "context": "private",
            }],
        },
    })

    assert result["threat_intel_score"] == 0
    assert result["risk_score"] == 30
    assert result["risk_level"] == "LOW"


def test_analyze_event_risk_preserves_original_event():
    event = {
        "severity": "HIGH",
        "event_type": "PORT_SCAN",
        "source_ip": "8.8.8.8",
    }

    result = analyze_event_risk(event)

    assert result["severity"] == "HIGH"
    assert result["event_type"] == "PORT_SCAN"
    assert result["source_ip"] == "8.8.8.8"
    assert result["risk_score"] == 85
    assert result["risk_level"] == "CRITICAL"
    assert result["threat_intel_score"] == 0


def test_missing_event_data_is_safe():
    result = calculate_risk_score({})

    assert result["risk_score"] == 20
    assert result["risk_level"] == "LOW"
    assert result["threat_intel_score"] == 0


def test_invalid_event_input_is_safe():
    result = calculate_risk_score(None)

    assert result["risk_score"] == 20
    assert result["risk_level"] == "LOW"
    assert result["threat_intel_score"] == 0
