from datetime import datetime
from event import SecurityEvent


FAILED_KEYWORDS = [
    "failed",
    "authentication failure",
    "invalid user"
]


def detect_brute_force(logs, threshold=3):
    failed_count = 0

    for log in logs:
        log = log.lower()

        for keyword in FAILED_KEYWORDS:
            if keyword in log:
                failed_count += 1
                break

    if failed_count >= threshold:
        return SecurityEvent(
            timestamp=datetime.now(),
            event_type="BRUTE_FORCE",
            severity="HIGH",
            message=f"{failed_count} failed authentication attempts detected"
        )

    return None


if __name__ == "__main__":
    test_logs = [
        "Failed password for invalid user admin",
        "Failed password for invalid user test",
        "Failed password for invalid user attacker"
    ]

    event = detect_brute_force(test_logs)

    if event:
        event.display()
    else:
        print("No brute-force activity detected")
