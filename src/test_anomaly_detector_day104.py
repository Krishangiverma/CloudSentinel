from datetime import datetime

import pytest

from src.analyzers.anomaly_detector import (
    AnomalyResult,
    detect_anomalies,
)
from src.models.event import SecurityEvent


def make_event(
    event_type="HEARTBEAT",
    severity="LOW",
    message="Routine system activity",
    ip_address="192.0.2.10",
):
    return SecurityEvent(
        timestamp=datetime(2026, 10, 21, 8, 0, 0),
        event_type=event_type,
        severity=severity,
        message=message,
        source="test",
        ip_address=ip_address,
        risk_score=17,
        risk_level="LOW",
    )


def test_normal_event_has_low_score():
    result = detect_anomalies([make_event()])[0]

    assert isinstance(result, AnomalyResult)
    assert result.anomaly_score == 0
    assert result.is_anomaly is False
    assert result.reasons == ()


def test_high_signal_event_has_explainable_score():
    result = detect_anomalies(
        [make_event("BRUTE_FORCE", "HIGH", "Repeated login failures")]
    )[0]

    assert result.anomaly_score == 60
    assert result.is_anomaly is True
    assert "high_severity" in result.reasons
    assert "high_signal_event_type" in result.reasons
    assert "authentication_failure_signal" in result.reasons


def test_repeated_ip_is_detected_within_batch():
    events = [
        make_event("HEARTBEAT", ip_address="192.0.2.50")
        for _ in range(3)
    ]

    results = detect_anomalies(events)

    assert len(results) == 3
    assert all(
        result.anomaly_score == 25 for result in results
    )
    assert all(
        "repeated_source_ip_in_batch" in result.reasons
        for result in results
    )
    assert all(not result.is_anomaly for result in results)


def test_missing_ip_does_not_create_ip_burst():
    events = [
        make_event(ip_address="N/A")
        for _ in range(4)
    ]

    results = detect_anomalies(events)

    assert all(result.anomaly_score == 0 for result in results)


def test_dictionary_events_are_supported():
    event = {
        "event_type": "LOGIN_FAILURE",
        "severity": "MEDIUM",
        "message": "Failed login for test user",
        "ip_address": "192.0.2.8",
    }

    result = detect_anomalies([event])[0]

    assert result.anomaly_score == 25
    assert result.is_anomaly is False
    assert "medium_severity" in result.reasons
    assert "authentication_failure_signal" in result.reasons


def test_threshold_changes_only_classification():
    event = make_event("BRUTE_FORCE", "HIGH")

    low_threshold = detect_anomalies([event], threshold=50)[0]
    high_threshold = detect_anomalies([event], threshold=70)[0]

    assert low_threshold.anomaly_score == high_threshold.anomaly_score
    assert low_threshold.is_anomaly is True
    assert high_threshold.is_anomaly is False


def test_input_event_and_existing_risk_score_are_unchanged():
    event = make_event("BRUTE_FORCE", "HIGH")
    original_score = event.risk_score
    original_severity = event.severity

    detect_anomalies([event])

    assert event.risk_score == original_score
    assert event.severity == original_severity


@pytest.mark.parametrize("threshold", [-1, 101])
def test_invalid_threshold_is_rejected(threshold):
    with pytest.raises(ValueError, match="threshold"):
        detect_anomalies([], threshold=threshold)


def test_invalid_burst_threshold_is_rejected():
    with pytest.raises(ValueError, match="burst_threshold"):
        detect_anomalies([], burst_threshold=1)


def test_empty_batch_returns_empty_results():
    assert detect_anomalies([]) == []
