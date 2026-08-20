from datetime import datetime
from collections import Counter

from src.models.event import SecurityEvent
from src.data.database import save_event
from config.settings import BRUTE_FORCE_THRESHOLD


# Failed-login related keywords
FAILED_KEYWORDS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "failed login"
]


def extract_ip(log_line):
    """
    Extract the IP address that appears after the word 'from'
    in an authentication log line.
    """

    parts = log_line.split()

    for i, part in enumerate(parts):
        if part == "from" and i + 1 < len(parts):
            return parts[i + 1]

    return "N/A"


def detect_suspicious_events(logs):
    """
    Analyze authentication logs and detect suspicious
    security activity.

    Detection rules:
    1. Three or more failed login attempts from the same IP
       -> BRUTE_FORCE / HIGH
    2. Individual failed login attempts that do not reach
       the brute-force threshold
       -> SUSPICIOUS_ACTIVITY / MEDIUM
    3. Normal sudo session open/close messages are ignored.
    """

    events = []

    # ---------------------------------------------------------
    # STEP 1: Count failed attempts for every IP
    # ---------------------------------------------------------

    failed_ips = Counter()

    for log_line in logs:

        lower_line = log_line.lower()

        # Check whether this is a failed-login related line
        if any(keyword in lower_line for keyword in FAILED_KEYWORDS):

            ip = extract_ip(log_line)

            if ip != "N/A":
                failed_ips[ip] += 1

    # ---------------------------------------------------------
    # STEP 2: Create security events
    # ---------------------------------------------------------

    processed_bruteforce_ips = set()

    for log_line in logs:

        lower_line = log_line.lower()

        # -----------------------------------------------------
        # Ignore normal sudo activity
        # -----------------------------------------------------

        if "sudo:" in lower_line:

            if (
                "session opened" in lower_line
                or "session closed" in lower_line
            ):
                continue

        # -----------------------------------------------------
        # Ignore logs that are not failed-login related
        # -----------------------------------------------------

        if not any(
            keyword in lower_line
            for keyword in FAILED_KEYWORDS
        ):
            continue

        # -----------------------------------------------------
        # Extract IP
        # -----------------------------------------------------

        ip = extract_ip(log_line)

        # -----------------------------------------------------
        # BRUTE-FORCE DETECTION
        # -----------------------------------------------------

        if (
            ip != "N/A"
            and failed_ips[ip] >= BRUTE_FORCE_THRESHOLD
            and ip not in processed_bruteforce_ips
        ):

            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type="BRUTE_FORCE",
                severity="HIGH",
                message=(
                    f"Brute-force attack detected from "
                    f"{ip}: {failed_ips[ip]} failed attempts"
                ),
                source="auth.log",
                ip_address=ip
            )

            events.append(event)

            processed_bruteforce_ips.add(ip)

        # -----------------------------------------------------
        # NORMAL SUSPICIOUS ACTIVITY
        # -----------------------------------------------------

        elif ip != "N/A":

            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type="SUSPICIOUS_ACTIVITY",
                severity="MEDIUM",
                message=log_line.strip(),
                source="auth.log",
                ip_address=ip
            )

            events.append(event)

    return events


# =============================================================
# TESTING
# =============================================================

if __name__ == "__main__":

    # Sample authentication logs for testing
    test_logs = [

        "sshd: Failed password for user admin from 192.168.1.50",

        "sshd: Failed password for user root from 192.168.1.50",

        "sshd: Failed password for user test from 192.168.1.50",

        "sudo: pam_unix(sudo:session): session opened for user root",

        "sudo: pam_unix(sudo:session): session closed for user root"
    ]

    # ---------------------------------------------------------
    # Run detection engine
    # ---------------------------------------------------------

    detected_events = detect_suspicious_events(test_logs)

    print()
    print("========================================")
    print("       CloudSentinel Detection Engine")
    print("========================================")
    print()

    print(
        f"Detected {len(detected_events)} suspicious events:"
    )

    print()

    # ---------------------------------------------------------
    # Display and save detected events
    # ---------------------------------------------------------

    for event in detected_events:

        print(
            f"[{event.severity}] "
            f"{event.event_type} | "
            f"IP={event.ip_address} | "
            f"{event.message}"
        )

        # Save each detected event into database
        save_event(event)

    print()
    print("Detection engine test completed.")
