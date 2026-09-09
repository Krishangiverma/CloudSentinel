"""
CloudSentinel Canonical Security Event Model.

This is the canonical event representation used between
ingestion, validation, detection, risk, correlation and
alerting components.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    """
    Canonical CloudSentinel security event.

    Required fields:

        timestamp
        event_type
        severity
        message
        source

    Optional:

        ip_address
    """

    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str = "UNKNOWN"
    ip_address: str = "N/A"

    def __post_init__(self):
        """
        Normalize fields that have well-defined canonical forms.
        """

        self.event_type = str(self.event_type).strip().upper()
        self.severity = str(self.severity).strip().upper()
        self.message = str(self.message).strip()
        self.source = str(self.source).strip()
        self.ip_address = str(self.ip_address).strip()

    def __str__(self):
        return (
            f"[{self.severity}] "
            f"{self.event_type} | "
            f"{self.timestamp} | "
            f"{self.source} | "
            f"IP={self.ip_address} | "
            f"{self.message}"
        )

    def display(self):
        """
        Display the security event in a readable format.
        """

        print(self)


if __name__ == "__main__":

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST_EVENT",
        severity="LOW",
        message="CloudSentinel canonical event model is working.",
        source="CloudSentinel",
        ip_address="127.0.0.1",
    )

    print("=== SecurityEvent Test ===")
    event.display()
