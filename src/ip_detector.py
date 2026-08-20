from datetime import datetime
import re
from event import SecurityEvent


def detect_brute_force_by_ip(logs, threshold=3):
    ip_counts = {}

    for log in logs:
        lower_log = log.lower()

        # Ignore logs that are not authentication failures
        if (
            "failed" not in lower_log
            and "authentication failure" not in lower_log
            and "invalid user" not in lower_log
        ):
            continue

        # Extract IPv4 addresses from the complete log
        ips = re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            log
        )

        if ips:
            ip = ips[0]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Check whether any IP reached the brute-force threshold
    for ip, count in ip_counts.items():
        if count >= threshold:
            return SecurityEvent(
                timestamp=datetime.now(),
                event_type="BRUTE_FORCE",
                severity="HIGH",
                message=f"Brute-force attack detected from {ip}: {count} failed attempts"
            )

    return None
