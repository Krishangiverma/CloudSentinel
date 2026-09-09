"""
CloudSentinel Event Validation.

Validates canonical SecurityEvent objects before they
enter the detection pipeline.
"""

import ipaddress
from datetime import datetime

from src.models.event import SecurityEvent


VALID_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


class EventValidationError(ValueError):
    """
    Raised when a security event violates the canonical schema.
    """


def validate_event(event):
    """
    Validate a canonical SecurityEvent.

    Returns:
        SecurityEvent

    Raises:
        EventValidationError
    """

    if not isinstance(event, SecurityEvent):
        raise EventValidationError(
            "Event must be a SecurityEvent instance."
        )

    if not isinstance(event.timestamp, datetime):
        raise EventValidationError(
            "timestamp must be a datetime instance."
        )

    if not isinstance(event.event_type, str):
        raise EventValidationError(
            "event_type must be a string."
        )

    if not event.event_type.strip():
        raise EventValidationError(
            "event_type cannot be empty."
        )

    if not isinstance(event.severity, str):
        raise EventValidationError(
            "severity must be a string."
        )

    if event.severity.upper() not in VALID_SEVERITIES:
        raise EventValidationError(
            f"Invalid severity: {event.severity}. "
            f"Allowed values: {sorted(VALID_SEVERITIES)}"
        )

    if not isinstance(event.message, str):
        raise EventValidationError(
            "message must be a string."
        )

    if not event.message.strip():
        raise EventValidationError(
            "message cannot be empty."
        )

    if not isinstance(event.source, str):
        raise EventValidationError(
            "source must be a string."
        )

    if not event.source.strip():
        raise EventValidationError(
            "source cannot be empty."
        )

    if not isinstance(event.ip_address, str):
        raise EventValidationError(
            "ip_address must be a string."
        )

    # N/A is explicitly allowed when an event has no IP.
    if event.ip_address != "N/A":

        try:
            ipaddress.ip_address(event.ip_address)

        except ValueError as error:
            raise EventValidationError(
                f"Invalid IP address: {event.ip_address}"
            ) from error

    return event
