
"""
CloudSentinel Canonical Security Event Model.

Canonical event representation shared by ingestion, validation,
detection, risk scoring, correlation, and alerting.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def _default_iocs():
    return {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }


@dataclass
class SecurityEvent:
    """
    Canonical CloudSentinel security event.

    Required fields:
        timestamp, event_type, severity, message

    Optional fields:
        source, ip_address, user, risk information,
        threat-intelligence data, and raw evidence.
    """

    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str = "UNKNOWN"
    ip_address: str = "N/A"
    user: str | None = None
    risk_score: int | float | None = None
    risk_level: str | None = None
    threat_intel_score: int | float = 0
    iocs: dict = field(default_factory=_default_iocs)
    threat_intel: dict = field(
        default_factory=lambda: {"total": 0, "items": []}
    )
    # Appended at the end to preserve existing positional arguments.
    raw_evidence: Any = None

    def __post_init__(self):
        self.event_type = str(self.event_type).strip().upper()
        self.severity = str(self.severity).strip().upper()
        self.message = str(self.message).strip()
        self.source = str(self.source).strip()
        self.ip_address = str(self.ip_address).strip()

        if self.user is not None:
            self.user = str(self.user).strip()

        if self.risk_level is not None:
            self.risk_level = str(self.risk_level).strip().upper()

        try:
            self.threat_intel_score = int(self.threat_intel_score)
        except (TypeError, ValueError, OverflowError):
            self.threat_intel_score = 0

        if not isinstance(self.iocs, dict):
            self.iocs = _default_iocs()

        if not isinstance(self.threat_intel, dict):
            self.threat_intel = {"total": 0, "items": []}

    def __str__(self):
        return (
            f"[{self.severity}] {self.event_type} | "
            f"{self.timestamp} | {self.source} | "
            f"IP={self.ip_address} | "
            f"Risk={self.risk_score} ({self.risk_level}) | "
            f"TI={self.threat_intel_score} | {self.message}"
        )

    def display(self):
        print(self)


if __name__ == "__main__":
    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST_EVENT",
        severity="LOW",
        message="CloudSentinel canonical event model is working.",
        source="CloudSentinel",
        ip_address="127.0.0.1",
        raw_evidence="Example original log entry",
    )
    print("=== SecurityEvent Test ===")
    event.display()
    print("Raw evidence:", event.raw_evidence)
