from datetime import datetime
from event import SecurityEvent


def detect_brute_force_by_ip(logs, threshold=3):
    ip_counts = {}

    for log in logs:
        lower_log = log.lower()

        if (
            "failed" not in lower_log
            and "authentication failure" not in lower_log
            and "invalid user" not in lower_log
        ):
            continue

        parts = log.split()

        if "from" in parts:
            ip = parts[parts.index("from") + 1]
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    for ip, count in ip_counts.items():
        if count >= threshold:
            return SecurityEvent(
                timestamp=datetime.now(),
                event_type="BRUTE_FORCE",
                severity="HIGH",
                message=f"Brute-force attack detected from {ip}: {count} failed attempts"
            )

    return None
