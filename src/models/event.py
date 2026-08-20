from dataclasses import dataclass
from datetime import datetime


@dataclass
class SecurityEvent:
    """
    Represents a security event detected by CloudSentinel.
    """

    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str
    ip_address: str = "N/A"

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


# Test event
if __name__ == "__main__":
    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST_EVENT",
        severity="LOW",
        message="CloudSentinel SecurityEvent model is working.",
        source="CloudSentinel",
        ip_address="127.0.0.1"
    )

    print("=== SecurityEvent Test ===")
    event.display()
