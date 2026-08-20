import re
from datetime import datetime

from models.event import SecurityEvent
from data.database import save_event

BRUTE_FORCE_THRESHOLD = 3


def detect_brute_force_by_ip(logs, threshold=BRUTE_FORCE_THRESHOLD):
    ip_counts = {}

    for log in logs:
        lower_log = log.lower()

        # Only authentication failures
        if (
            "failed" not in lower_log
            and "authentication failure" not in lower_log
            and "invalid user" not in lower_log
        ):
            continue

        # Extract IPv4 address
        ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            log
        )

        if not ips:
            continue

        ip = ips[0]
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Detect brute-force attack
    for ip, count in ip_counts.items():
        if count >= threshold:
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type="BRUTE_FORCE",
                severity="HIGH",
                message=(
                    f"Brute-force attack detected from "
                    f"{ip}: {count} failed attempts"
                ),
                source="auth.log",
                ip_address=ip
            )

            save_event(event)
            return event

    return None


if __name__ == "__main__":

    test_logs = [
        "Failed password for invalid user admin from 192.168.1.50",
        "Failed password for invalid user root from 192.168.1.50",
        "Failed password for invalid user test from 192.168.1.50"
    ]

    event = detect_brute_force_by_ip(test_logs)

    if event:
        event.display()
        print("\nEvent saved to CloudSentinel database.")
    else:
        print("No brute-force attack detected.")
