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

    def __str__(self):
        return (
            f"[{self.timestamp}] "
            f"{self.severity} | "
            f"{self.event_type} | "
            f"{self.source} | "
            f"{self.message}"
        )


# Test event
if __name__ == "__main__":
    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="TEST_EVENT",
        severity="LOW",
        message="CloudSentinel SecurityEvent model is working.",
        source="CloudSentinel"
    )

    print("=== SecurityEvent Test ===")
    print(event)
