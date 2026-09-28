from datetime import datetime
from pathlib import Path

from src.models.event import SecurityEvent
from src.data.database import save_event
from src.ingestion import ingest_event


# Ubuntu security log location
LOG_PATH = Path("/var/log/auth.log")


def read_security_logs():
    """
    Read security-related entries from Ubuntu auth.log.

    Return an empty list when the log is missing or cannot be read.
    Avoid printing exception messages that may contain sensitive details.
    """
    try:
        if not LOG_PATH.exists():
            print("Security log not found.")
            return []

        with open(LOG_PATH, "r", errors="ignore") as file:
            return file.readlines()

    except PermissionError:
        print("Permission denied while reading auth.log.")
        print("Check the permissions for the security log.")
        return []

    except OSError as exc:
        print(
            f"Security log read failed ({type(exc).__name__})."
        )
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
    Read security logs, normalize and validate events, and save them.

    A limit of zero processes no events. Negative limits are rejected.
    Individual event failures are logged without exposing raw log content.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be a non-negative integer")

    if limit < 0:
        raise ValueError("limit must be non-negative")

    if limit == 0:
        print("Security log limit is zero; no events processed.")
        return 0

    logs = read_security_logs()

    if not logs:
        print("No security logs found.")
        return 0

    saved_count = 0
    failed_count = 0

    for log_line in logs[-limit:]:
        try:
            event = create_security_event(log_line)
            event = ingest_event(event)
            save_event(event)
            saved_count += 1
        except Exception as exc:
            failed_count += 1
            print(
                f"Security log event processing failed "
                f"({type(exc).__name__}); continuing."
            )

    print(f"{saved_count} security events saved to database.")
    if failed_count:
        print(f"{failed_count} security log events failed processing.")

    return saved_count


if __name__ == "__main__":
    print("=== CloudSentinel Security Log Collector ===")

    collect_and_save_events(limit=20)

    print("Security log collection completed.")
