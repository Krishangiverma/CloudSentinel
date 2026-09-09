"""
Tests for the CloudSentinel canonical event pipeline.
"""

from datetime import datetime

from src.ingestion import (
    EventPipeline,
    EventValidationError,
    normalize_event,
    validate_event,
)
from src.models.event import SecurityEvent


def test_normalize_dictionary():

    raw_event = {
        "event_type": "brute_force",
        "severity": "high",
        "message": "Multiple failed login attempts from 192.168.1.50",
        "source": "auth.log",
        "ip": "192.168.1.50",
    }

    event = normalize_event(raw_event)

    assert isinstance(event, SecurityEvent)
    assert event.event_type == "BRUTE_FORCE"
    assert event.severity == "HIGH"
    assert event.ip_address == "192.168.1.50"


def test_normalize_string():

    event = normalize_event(
        "Failed password for invalid user from 10.0.0.5"
    )

    assert isinstance(event, SecurityEvent)
    assert event.event_type == "SECURITY_LOG"
    assert event.ip_address == "10.0.0.5"


def test_existing_security_event_is_preserved():

    original = SecurityEvent(
        timestamp=datetime.now(),
        event_type="BRUTE_FORCE",
        severity="HIGH",
        message="Attack detected",
        source="auth.log",
        ip_address="192.168.1.10",
    )

    normalized = normalize_event(original)

    assert normalized is original


def test_valid_event():

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="BRUTE_FORCE",
        severity="HIGH",
        message="Brute force detected",
        source="auth.log",
        ip_address="192.168.1.10",
    )

    assert validate_event(event) is event


def test_invalid_severity():

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST",
        severity="UNKNOWN",
        message="Test event",
        source="test",
    )

    try:
        validate_event(event)
        assert False, "Expected EventValidationError"

    except EventValidationError:
        pass


def test_invalid_ip():

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST",
        severity="LOW",
        message="Test event",
        source="test",
        ip_address="999.999.999.999",
    )

    try:
        validate_event(event)
        assert False, "Expected EventValidationError"

    except EventValidationError:
        pass


def test_empty_message():

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST",
        severity="LOW",
        message="",
        source="test",
    )

    try:
        validate_event(event)
        assert False, "Expected EventValidationError"

    except EventValidationError:
        pass


def test_pipeline_processes_event():

    pipeline = EventPipeline()

    event = pipeline.ingest(
        {
            "event_type": "suspicious_login",
            "severity": "medium",
            "message": "Suspicious login from 10.0.0.25",
            "source": "auth.log",
            "ip": "10.0.0.25",
        }
    )

    assert event.event_type == "SUSPICIOUS_LOGIN"
    assert event.severity == "MEDIUM"
    assert event.ip_address == "10.0.0.25"
    assert pipeline.events_processed == 1
    assert pipeline.events_rejected == 0


def test_pipeline_rejects_invalid_event():

    pipeline = EventPipeline()

    try:
        pipeline.ingest(
            {
                "event_type": "TEST",
                "severity": "INVALID",
                "message": "Invalid event",
                "source": "test",
            }
        )

        assert False, "Expected EventValidationError"

    except EventValidationError:
        assert pipeline.events_rejected == 1
