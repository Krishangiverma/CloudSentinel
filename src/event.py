from dataclasses import dataclass
from datetime import datetime


SEVERITY_LEVELS = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5
}


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    message: str
    source: str = "auth.log"

    def __post_init__(self):
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity: {self.severity}"
            )

    def display(self):
        print(
            f"[{self.severity}] "
            f"{self.event_type} | "
            f"{self.timestamp} | "
            f"{self.message}"
        )


if __name__ == "__main__":
    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type="FAILED_LOGIN",
        severity="MEDIUM",
        message="Failed authentication attempt detected"
    )

    event.display()
