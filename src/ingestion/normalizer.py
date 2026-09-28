
"""Normalize incoming security data into SecurityEvent objects."""

import re
from datetime import datetime
from typing import Any

from src.models.event import SecurityEvent


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip(value):
    """Extract a dotted-quad candidate from a string."""
    if not isinstance(value, str):
        return "N/A"

    match = IP_PATTERN.search(value)
    return match.group(0) if match else "N/A"


def _get_value(event, key, default=None):
    """Read a field from a dictionary or an object."""
    if isinstance(event, dict):
        return event.get(key, default)

    return getattr(event, key, default)


def _normalize_timestamp(value):
    """
    Return a datetime for a datetime or ISO-8601 timestamp string.

    Missing timestamps use the current time. Supplied invalid timestamps
    raise ValueError rather than being silently replaced.
    """
    if value is None:
        return datetime.now()

    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        timestamp_text = value.strip()

        if not timestamp_text:
            raise ValueError("timestamp cannot be an empty string.")

        # Python's fromisoformat accepts +00:00; convert the common UTC
        # suffix Z (or z) into that form.
        if timestamp_text.endswith(("Z", "z")):
            timestamp_text = timestamp_text[:-1] + "+00:00"

        try:
            return datetime.fromisoformat(timestamp_text)
        except ValueError as error:
            raise ValueError(
                f"Invalid ISO-8601 timestamp: {value!r}"
            ) from error

    raise ValueError(
        "timestamp must be a datetime instance or ISO-8601 string."
    )


def normalize_event(event):
    """
    Normalize a SecurityEvent, raw log string, dictionary, or object.

    Existing SecurityEvent objects are returned unchanged.
    Original input is retained as raw_evidence unless an explicit
    raw_evidence field is supplied.
    """
    if isinstance(event, SecurityEvent):
        return event

    if isinstance(event, str):
        message = event.strip()

        return SecurityEvent(
            timestamp=datetime.now(),
            event_type="SECURITY_LOG",
            severity="LOW",
            message=message,
            source="unknown",
            ip_address=extract_ip(message),
            raw_evidence=event,
        )

    if event is None:
        raise ValueError("event cannot be None.")

    timestamp = _normalize_timestamp(_get_value(event, "timestamp"))
    event_type = _get_value(event, "event_type", "SECURITY_LOG")
    severity = _get_value(event, "severity", "LOW")
    message = _get_value(event, "message", "")
    source = _get_value(event, "source", "unknown")

    ip_address = _get_value(event, "ip_address")
    if not ip_address:
        ip_address = _get_value(event, "ip")

    if not ip_address:
        ip_address = extract_ip(message)

    user = _get_value(event, "user")
    raw_evidence = _get_value(event, "raw_evidence", event)

    return SecurityEvent(
        timestamp=timestamp,
        event_type=str(event_type).upper(),
        severity=str(severity).upper(),
        message=str(message),
        source=str(source),
        ip_address=str(ip_address),
        user=user,
        risk_score=_get_value(event, "risk_score"),
        risk_level=_get_value(event, "risk_level"),
        threat_intel_score=_get_value(event, "threat_intel_score", 0),
        iocs=_get_value(event, "iocs"),
        threat_intel=_get_value(event, "threat_intel"),
        raw_evidence=raw_evidence,
    )
