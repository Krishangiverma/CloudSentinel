"""
Day 35 tests for the CloudSentinel attack correlation engine.
"""

from src.analyzers.attack_correlator import correlate_events


def make_event(
    event_id,
    timestamp,
    event_type,
    risk_score,
    ip_address="192.168.1.50",
):
    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": "HIGH",
        "message": f"Test event {event_id}",
        "source": "test",
        "ip_address": ip_address,
        "risk_score": risk_score,
    }


def test_events_below_threshold_do_not_create_incident():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            40,
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "FAILED_LOGIN",
            40,
        ),
    ]

    incidents = correlate_events(
        events,
        threshold=3,
    )

    assert incidents == []


def test_same_ip_events_create_incident():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            45,
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "BRUTE_FORCE",
            80,
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "SUSPICIOUS_LOGIN",
            55,
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["incident_id"] == "INC-0001"
    assert incident["ip_address"] == "192.168.1.50"
    assert incident["event_count"] == 3
    assert incident["max_risk_score"] == 80
    assert incident["risk_level"] == "CRITICAL"
    assert incident["attack_pattern"] == "BRUTE_FORCE_ACTIVITY"
    assert incident["status"] == "OPEN"


def test_incident_contains_correlated_event_timeline():

    events = [
        make_event(
            3,
            "2026-09-14T10:03:00",
            "BRUTE_FORCE",
            80,
        ),
        make_event(
            1,
            "2026-09-14T10:01:00",
            "FAILED_LOGIN",
            45,
        ),
        make_event(
            2,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            45,
        ),
    ]

    incidents = correlate_events(events)

    incident = incidents[0]

    assert incident["first_seen"] == "2026-09-14T10:01:00"
    assert incident["last_seen"] == "2026-09-14T10:03:00"

    assert [
        event["id"]
        for event in incident["events"]
    ] == [1, 2, 3]


def test_different_ips_create_separate_incidents():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "BRUTE_FORCE",
            80,
            "10.0.0.10",
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "BRUTE_FORCE",
            80,
            "10.0.0.10",
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "BRUTE_FORCE",
            80,
            "10.0.0.10",
        ),
        make_event(
            4,
            "2026-09-14T10:03:00",
            "MALWARE",
            100,
            "10.0.0.20",
        ),
        make_event(
            5,
            "2026-09-14T10:04:00",
            "MALWARE",
            100,
            "10.0.0.20",
        ),
        make_event(
            6,
            "2026-09-14T10:05:00",
            "MALWARE",
            100,
            "10.0.0.20",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 2

    assert incidents[0]["ip_address"] == "10.0.0.10"
    assert incidents[0]["attack_pattern"] == "BRUTE_FORCE_ACTIVITY"

    assert incidents[1]["ip_address"] == "10.0.0.20"
    assert incidents[1]["attack_pattern"] == "MALWARE_ACTIVITY"


def test_invalid_ip_events_are_ignored():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "TEST",
            20,
            "N/A",
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "TEST",
            20,
            "UNKNOWN",
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "TEST",
            20,
            "",
        ),
    ]

    incidents = correlate_events(events)

    assert incidents == []


def test_invalid_threshold_is_rejected():

    try:
        correlate_events([], threshold=0)
        assert False, "Expected ValueError"
    except ValueError as error:
        assert "at least 1" in str(error)
