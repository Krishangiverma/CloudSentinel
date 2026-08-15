from datetime import datetime
from event import SecurityEvent


FAILED_KEYWORDS = [
    "failed",
    "authentication failure",
    "invalid user"
]


def detect_suspicious_event(log_line):
    lower_line = log_line.lower()

    for keyword in FAILED_KEYWORDS:
        if keyword in lower_line:
            return SecurityEvent(
                timestamp=datetime.now(),
                event_type="FAILED_LOGIN",
                severity="MEDIUM",
                message=log_line
            )

    return None


if __name__ == "__main__":
    test_log = "Failed password for invalid user attacker"

    event = detect_suspicious_event(test_log)

    if event:
        event.display()
    else:
        print("Normal event")
