"""
CloudSentinel tests for the advanced attack correlation engine.
"""

from src.analyzers.attack_correlator import correlate_events


# ============================================================
# TEST EVENT FACTORY
# ============================================================

def make_event(
    event_id,
    timestamp,
    event_type,
    risk_score,
    ip_address="192.168.1.50",
    user=None,
):
    return {
        "id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": "HIGH",
        "message": f"Test event {event_id}",
        "source": "test",
        "ip_address": ip_address,
        "user": user,
        "risk_score": risk_score,
    }


# ============================================================
# BASIC CORRELATION TESTS
# ============================================================

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
    assert (
        incidents[0]["attack_pattern"]
        == "BRUTE_FORCE_ACTIVITY"
    )

    assert incidents[1]["ip_address"] == "10.0.0.20"
    assert (
        incidents[1]["attack_pattern"]
        == "MALWARE_ACTIVITY"
    )


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
        correlate_events(
            [],
            threshold=0,
        )

        assert False, "Expected ValueError"

    except ValueError as error:
        assert "at least 1" in str(error)


# ============================================================
# DAY 43 — ADVANCED INCIDENT CORRELATION
# ============================================================

def test_incident_contains_threat_intelligence_context():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "BRUTE_FORCE",
            80,
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "SUSPICIOUS_LOGIN",
            70,
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            40,
        ),
    ]

    events[0]["risk_level"] = "CRITICAL"
    events[0]["threat_intel_score"] = 30

    events[1]["risk_level"] = "HIGH"
    events[1]["threat_intel_score"] = 20

    events[2]["risk_level"] = "MEDIUM"
    events[2]["threat_intel_score"] = 0

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["total_threat_intel_score"] == 50
    assert incident["max_threat_intel_score"] == 30
    assert incident["critical_event_count"] == 1
    assert incident["high_risk_event_count"] == 1

    assert "investigation_summary" in incident

    assert "BRUTE FORCE ACTIVITY" in (
        incident["investigation_summary"].upper()
    )


def test_incident_without_threat_intelligence_remains_backward_compatible():

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
        make_event(
            3,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            40,
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["total_threat_intel_score"] == 0
    assert incident["max_threat_intel_score"] == 0
    assert incident["critical_event_count"] == 0
    assert incident["high_risk_event_count"] == 0


# ============================================================
# DAY 43 — IOC AGGREGATION
# ============================================================

def test_incident_aggregates_unique_iocs():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "BRUTE_FORCE",
            80,
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
            "BRUTE_FORCE",
            80,
        ),
    ]

    events[0]["iocs"] = {
        "ips": ["8.8.8.8"],
        "domains": ["malicious.example.com"],
        "hashes": {
            "md5": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "sha1": [],
            "sha256": [],
        },
    }

    events[1]["iocs"] = {
        "ips": ["8.8.8.8"],
        "domains": ["malicious.example.com"],
        "hashes": {
            "md5": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "sha1": [
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ],
            "sha256": [],
        },
    }

    events[2]["iocs"] = {
        "ips": ["1.1.1.1"],
        "domains": ["another.example.com"],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            ],
        },
    }

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["iocs"]["ips"] == [
        "1.1.1.1",
        "8.8.8.8",
    ]

    assert incident["iocs"]["domains"] == [
        "another.example.com",
        "malicious.example.com",
    ]

    assert incident["iocs"]["hashes"]["md5"] == [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ]

    assert incident["iocs"]["hashes"]["sha1"] == [
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]

    assert incident["iocs"]["hashes"]["sha256"] == [
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ]


def test_incident_risk_and_threat_intel_breakdown():

    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "BRUTE_FORCE",
            100,
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "SUSPICIOUS_LOGIN",
            70,
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            45,
        ),
        make_event(
            4,
            "2026-09-14T10:03:00",
            "FAILED_LOGIN",
            20,
        ),
    ]

    events[0]["risk_level"] = "CRITICAL"
    events[0]["threat_intel_score"] = 10

    events[1]["risk_level"] = "HIGH"
    events[1]["threat_intel_score"] = 5

    events[2]["risk_level"] = "MEDIUM"
    events[2]["threat_intel_score"] = 0

    events[3]["risk_level"] = "LOW"
    events[3]["threat_intel_score"] = 0

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["event_count"] == 4

    assert incident["critical_event_count"] == 1
    assert incident["high_risk_event_count"] == 1

    assert incident["total_threat_intel_score"] == 15
    assert incident["max_threat_intel_score"] == 10

    assert incident["risk_level"] == "CRITICAL"
    assert incident["max_risk_score"] == 100

    assert "iocs" in incident
    assert "ips" in incident["iocs"]
    assert "domains" in incident["iocs"]
    assert "hashes" in incident["iocs"]


def test_incident_without_iocs_returns_empty_ioc_structure():

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
        make_event(
            3,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            40,
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["iocs"] == {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }


# ============================================================
# DAY 61 — TEMPORAL + IDENTITY CORRELATION
# ============================================================

def test_same_ip_events_outside_time_window_split_incidents():
    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            40,
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
            "SUSPICIOUS_LOGIN",
            55,
            "10.0.0.10",
        ),
        make_event(
            4,
            "2026-09-14T10:20:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
        ),
        make_event(
            5,
            "2026-09-14T10:21:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
        ),
        make_event(
            6,
            "2026-09-14T10:22:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
        ),
    ]

    incidents = correlate_events(
        events,
        time_window_seconds=300,
    )

    assert len(incidents) == 2
    assert incidents[0]["event_count"] == 3
    assert incidents[1]["event_count"] == 3
    assert [
        event["id"] for event in incidents[0]["events"]
    ] == [1, 2, 3]
    assert [
        event["id"] for event in incidents[1]["events"]
    ] == [4, 5, 6]


def test_same_user_across_different_ips_correlates():
    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
            user="alice",
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "SUSPICIOUS_LOGIN",
            55,
            "10.0.0.20",
            user="alice",
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "BRUTE_FORCE",
            80,
            "10.0.0.30",
            user="alice",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1

    incident = incidents[0]

    assert incident["ip_address"] == "MULTIPLE"
    assert incident["source_ips"] == [
        "10.0.0.10",
        "10.0.0.20",
        "10.0.0.30",
    ]
    assert incident["users"] == ["alice"]
    assert incident["event_count"] == 3


def test_different_user_and_ip_do_not_correlate():
    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
            user="alice",
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.20",
            user="bob",
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.30",
            user="charlie",
        ),
    ]

    incidents = correlate_events(events)

    assert incidents == []


def test_day61_correlation_metadata_contains_relationships():
    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
            user="alice",
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "SUSPICIOUS_LOGIN",
            55,
            "10.0.0.10",
            user="alice",
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "BRUTE_FORCE",
            80,
            "10.0.0.20",
            user="alice",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1

    correlation = incidents[0]["correlation"]

    assert correlation["method"] == (
        "TEMPORAL_IDENTITY_EVENT_CORRELATION"
    )
    assert correlation["time_window_seconds"] == 300
    assert correlation["source_ips"] == [
        "10.0.0.10",
        "10.0.0.20",
    ]
    assert correlation["users"] == ["alice"]

    relationships = correlation["relationships"]

    assert relationships
    assert any(
        "SAME_SOURCE_IP" in relationship["reasons"]
        for relationship in relationships
    )
    assert any(
        "SAME_USER" in relationship["reasons"]
        for relationship in relationships
    )
    assert all(
        "WITHIN_TIME_WINDOW" in relationship["reasons"]
        for relationship in relationships
    )


def test_day61_invalid_time_window_is_rejected():
    try:
        correlate_events(
            [],
            time_window_seconds=-1,
        )
        assert False, "Expected ValueError"
    except ValueError as error:
        assert "cannot be negative" in str(error)


def test_day61_user_matching_is_case_insensitive():
    events = [
        make_event(
            1,
            "2026-09-14T10:00:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.10",
            user="Alice",
        ),
        make_event(
            2,
            "2026-09-14T10:01:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.20",
            user="alice",
        ),
        make_event(
            3,
            "2026-09-14T10:02:00",
            "FAILED_LOGIN",
            40,
            "10.0.0.30",
            user="ALICE",
        ),
    ]

    incidents = correlate_events(events)

    assert len(incidents) == 1
    assert incidents[0]["users"] == ["alice"]
