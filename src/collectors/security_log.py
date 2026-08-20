from datetime import datetime
from pathlib import Path

from src.models.event import SecurityEvent
from src.data.database import save_event


# Ubuntu security log location
LOG_PATH = Path("/var/log/auth.log")


def read_security_logs():
    """
    Read security-related entries from Ubuntu auth.log.
    """

    if not LOG_PATH.exists():
        print(f"Security log not found: {LOG_PATH}")
        return []

    try:
        with open(LOG_PATH, "r", errors="ignore") as file:
            return file.readlines()

    except PermissionError:
        print("Permission denied while reading auth.log.")
        print("Try running the program with sudo.")
        return []


def detect_event_type(log_line):
    """
    Identify the type of security event from a log line.
    """

    line = log_line.lower()

    if "failed password" in line:
        return "FAILED_LOGIN"

    if "authentication failure" in line:
        return "AUTH_FAILURE"

    if "accepted password" in line:
        return "SUCCESSFUL_LOGIN"

    if "accepted publickey" in line:
        return "SUCCESSFUL_SSH_LOGIN"

    if "sudo:" in line:
        return "SUDO_ACTIVITY"

    if "invalid user" in line:
        return "INVALID_USER"

    return "SECURITY_LOG"


def detect_severity(event_type):
    """
    Assign severity according to the event type.
    """

    if event_type in ["FAILED_LOGIN", "AUTH_FAILURE", "INVALID_USER"]:
        return "HIGH"

    if event_type == "SUDO_ACTIVITY":
        return "MEDIUM"

    if event_type in ["SUCCESSFUL_LOGIN", "SUCCESSFUL_SSH_LOGIN"]:
        return "LOW"

    return "LOW"


def create_security_event(log_line):
    """
    Convert a raw log line into a SecurityEvent object.
    """

    event_type = detect_event_type(log_line)
    severity = detect_severity(event_type)

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type=event_type,
        severity=severity,
        message=log_line.strip(),
        source="Ubuntu auth.log"
    )

    return event


def collect_and_save_events(limit=20):
    """
    Read security logs, convert them into SecurityEvent objects,
    and save them into the CloudSentinel database.
    """

    logs = read_security_logs()

    if not logs:
        print("No security logs found.")
        return 0

    saved_count = 0

    # Process latest log entries first
    for log_line in logs[-limit:]:
        event = create_security_event(log_line)

        save_event(event)

        saved_count += 1

    print(f"{saved_count} security events saved to database.")

    return saved_count


if __name__ == "__main__":
    print("=== CloudSentinel Security Log Collector ===")

    collect_and_save_events(limit=20)

    print("Security log collection completed.")
