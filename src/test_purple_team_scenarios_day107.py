"""Day 107: Synthetic anomaly-detection scenario validation."""

from src.analyzers.anomaly_detector import detect_anomalies


def event(
    event_type="HEARTBEAT",
    severity="LOW",
    message="Routine system activity",
    ip_address="192.0.2.10",
):
    return {
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "ip_address": ip_address,
    }


def test_benign_event_is_not_flagged():
    result = detect_anomalies([
        event(ip_address="192.0.2.11")
    ])[0]

    assert result.anomaly_score == 0
    assert result.is_anomaly is False
    assert result.reasons == ()


def test_single_failed_login_is_explained_but_below_default_threshold():
    result = detect_anomalies([
        event(
            event_type="LOGIN_FAILURE",
            message="Failed login for synthetic user",
            ip_address="192.0.2.12",
        )
    ])[0]

    assert result.anomaly_score == 15
    assert result.is_anomaly is False
    assert "authentication_failure_signal" in result.reasons


def test_repeated_failed_logins_cross_explicit_threshold():
    events = [
        event(
            event_type="LOGIN_FAILURE",
            message="Failed login for synthetic user",
            ip_address="192.0.2.13",
        )
        for _ in range(3)
    ]

    results = detect_anomalies(events, threshold=40)

    assert len(results) == 3
    assert all(result.anomaly_score == 40 for result in results)
    assert all(result.is_anomaly for result in results)
    assert all(
        "authentication_failure_signal" in result.reasons
        and "repeated_source_ip_in_batch" in result.reasons
        for result in results
    )


def test_high_severity_brute_force_has_explainable_score():
    result = detect_anomalies([
        event(
            event_type="BRUTE_FORCE",
            severity="HIGH",
            message="Repeated login failures",
            ip_address="192.0.2.14",
        )
    ])[0]

    assert result.anomaly_score == 60
    assert result.is_anomaly is True
    assert "high_severity" in result.reasons
    assert "high_signal_event_type" in result.reasons
    assert "authentication_failure_signal" in result.reasons


def test_repeated_ip_on_benign_events_exposes_frequency_false_positive_risk():
    events = [
        event(ip_address="192.0.2.15")
        for _ in range(3)
    ]

    results = detect_anomalies(events)

    assert all(result.anomaly_score == 25 for result in results)
    assert all(not result.is_anomaly for result in results)
    assert all(
        "repeated_source_ip_in_batch" in result.reasons
        for result in results
    )


def test_missing_ip_does_not_trigger_repeated_ip_signal():
    events = [
        event(ip_address="N/A")
        for _ in range(4)
    ]

    results = detect_anomalies(events)

    assert all(result.anomaly_score == 0 for result in results)
    assert all(
        "repeated_source_ip_in_batch" not in result.reasons
        for result in results
    )


def test_detection_does_not_mutate_input_events():
    original = event(
        event_type="BRUTE_FORCE",
        severity="HIGH",
        message="Repeated login failures",
        ip_address="192.0.2.16",
    )
    before = original.copy()

    detect_anomalies([original])

    assert original == before
