"""
CloudSentinel Canonical Security Event Model.

This is the canonical event representation used between
ingestion, validation, detection, risk, correlation and
alerting components.
"""

from dataclasses import dataclass, field
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
        risk_score
        risk_level
        threat_intel_score
        iocs
        threat_intel
    """

    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str = "UNKNOWN"
    ip_address: str = "N/A"
    risk_score: int | float | None = None
    risk_level: str | None = None

    # --------------------------------------------------------
    # Threat-intelligence enrichment
    # --------------------------------------------------------

    threat_intel_score: int | float = 0

    iocs: dict = field(
        default_factory=lambda: {
            "ips": [],
            "domains": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
            },
        }
    )

    threat_intel: dict = field(
        default_factory=lambda: {
            "total": 0,
            "items": [],
        }
    )

    def __post_init__(self):
        """
        Normalize fields that have well-defined canonical forms.
        """

        self.event_type = str(
            self.event_type
        ).strip().upper()

        self.severity = str(
            self.severity
        ).strip().upper()

        self.message = str(
            self.message
        ).strip()

        self.source = str(
            self.source
        ).strip()

        self.ip_address = str(
            self.ip_address
        ).strip()

        if self.risk_level is not None:

            self.risk_level = str(
                self.risk_level
            ).strip().upper()

        try:
            self.threat_intel_score = int(
                self.threat_intel_score
            )

        except (TypeError, ValueError):

            self.threat_intel_score = 0

        if not isinstance(
            self.iocs,
            dict
        ):

            self.iocs = {
                "ips": [],
                "domains": [],
                "hashes": {
                    "md5": [],
                    "sha1": [],
                    "sha256": [],
                },
            }

        if not isinstance(
            self.threat_intel,
            dict
        ):

            self.threat_intel = {
                "total": 0,
                "items": [],
            }

    def __str__(self):

        return (
            f"[{self.severity}] "
            f"{self.event_type} | "
            f"{self.timestamp} | "
            f"{self.source} | "
            f"IP={self.ip_address} | "
            f"Risk={self.risk_score} "
            f"({self.risk_level}) | "
            f"TI={self.threat_intel_score} | "
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
