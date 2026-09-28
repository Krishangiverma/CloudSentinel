from datetime import datetime, timezone

import pytest

from src.ingestion.normalizer import normalize_event
from src.ingestion.validator import EventValidationError, validate_event
from src.models.event import SecurityEvent


def test_iso_timestamp_is_normalized():
    event = normalize_event({
        "timestamp": "2026-10-11T10:30:00Z",
        "event_type": "login_failure",
        "severity": "high",
        "message": "Failed login",
        "source": "auth.log",
    })

    assert isinstance(event.timestamp, datetime)
    assert event.timestamp == datetime(
        2026, 10, 11, 10, 30, tzinfo=timezone.utc
    )
    assert event.event_type == "LOGIN_FAILURE"
    assert validate_event(event) is event


def test_invalid_timestamp_is_not_silently_replaced():
    with pytest.raises(ValueError, match="Invalid ISO-8601 timestamp"):
        normalize_event({
            "timestamp": "not-a-timestamp",
            "event_type": "LOGIN_FAILURE",
            "severity": "HIGH",
            "message": "Failed login",
            "source": "auth.log",
        })


def test_unsupported_timestamp_type_is_rejected():
    with pytest.raises(ValueError, match="timestamp must be"):
        normalize_event({
            "timestamp": 12345,
            "event_type": "LOGIN_FAILURE",
            "severity": "HIGH",
            "message": "Failed login",
        })


def test_user_and_explicit_raw_evidence_are_preserved():
    evidence = "original authentication record"

    event = normalize_event({
        "timestamp": "2026-10-11T10:30:00",
        "event_type": "login_failure",
        "severity": "HIGH",
        "message": "Failed login",
        "source": "auth.log",
        "user": "alice",
        "raw_evidence": evidence,
    })

    assert event.user == "alice"
    assert event.raw_evidence == evidence


def test_original_dictionary_is_preserved_as_fallback_evidence():
    original = {
        "timestamp": "2026-10-11T10:30:00",
        "event_type": "LOGIN_FAILURE",
        "severity": "HIGH",
        "message": "Failed login",
        "source": "auth.log",
        "user": "alice",
    }

    event = normalize_event(original)

    assert event.raw_evidence is original
    assert event.user == "alice"


def test_raw_string_is_preserved_as_evidence():
    original = "  Failed password for alice from 192.0.2.10  "

    event = normalize_event(original)

    assert event.message == original.strip()
    assert event.raw_evidence == original
    assert event.ip_address == "192.0.2.10"
    assert validate_event(event) is event


def test_existing_security_event_is_returned_unchanged():
    original = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST",
        severity="LOW",
        message="Existing event",
    )

    assert normalize_event(original) is original


def test_validator_rejects_string_timestamp_on_direct_event():
    event = SecurityEvent(
        timestamp="not-a-datetime",
        event_type="TEST",
        severity="LOW",
        message="Test event",
    )

    with pytest.raises(EventValidationError, match="timestamp"):
        validate_event(event)


def test_optional_raw_evidence_does_not_break_old_constructors():
    event = SecurityEvent(
        datetime.now(),
        "TEST",
        "LOW",
        "Legacy constructor",
        "unit-test",
        "N/A",
    )

    assert event.source == "unit-test"
    assert event.ip_address == "N/A"
    assert event.raw_evidence is None
    assert validate_event(event) is event
