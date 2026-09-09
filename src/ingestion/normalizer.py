"""
CloudSentinel Event Normalizer.

Converts supported raw event formats into the canonical
SecurityEvent representation.
"""

import re
from datetime import datetime

from src.models.event import SecurityEvent


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)


def extract_ip(value):
    """
    Extract an IPv4 address from text.
    """

    if not isinstance(value, str):
        return "N/A"

    match = IP_PATTERN.search(value)

    if match:
        return match.group(0)

    return "N/A"


def _get_value(event, key, default=None):
    """
    Read a field from either a dictionary or an object.
    """

    if isinstance(event, dict):
        return event.get(key, default)

    return getattr(event, key, default)


def normalize_event(event):
    """
    Normalize a raw event into the canonical SecurityEvent model.

    Supported inputs:

    - SecurityEvent
    - dictionary
    - raw log string

    Returns:
        SecurityEvent
    """

    if isinstance(event, SecurityEvent):
        return event

    # ---------------------------------------------------------
    # Raw string event
    # ---------------------------------------------------------

    if isinstance(event, str):

        message = event.strip()

        return SecurityEvent(
            timestamp=datetime.now(),
            event_type="SECURITY_LOG",
            severity="LOW",
            message=message,
            source="unknown",
            ip_address=extract_ip(message),
        )

    # ---------------------------------------------------------
    # Dictionary/object event
    # ---------------------------------------------------------

    timestamp = _get_value(event, "timestamp")

    if timestamp is None:
        timestamp = datetime.now()

    event_type = _get_value(
        event,
        "event_type",
        "SECURITY_LOG",
    )

    severity = _get_value(
        event,
        "severity",
        "LOW",
    )

    message = _get_value(
        event,
        "message",
        "",
    )

    source = _get_value(
        event,
        "source",
        "unknown",
    )

    # Support both historical "ip" and canonical "ip_address".
    ip_address = _get_value(event, "ip_address")

    if ip_address is None:
        ip_address = _get_value(event, "ip")

    if not ip_address:
        ip_address = extract_ip(message)

    return SecurityEvent(
        timestamp=timestamp,
        event_type=str(event_type).upper(),
        severity=str(severity).upper(),
        message=str(message),
        source=str(source),
        ip_address=str(ip_address),
    )
