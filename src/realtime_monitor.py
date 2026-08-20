import time
import re
from pathlib import Path
from collections import Counter, deque
from datetime import datetime

from config.settings import AUTH_LOG_PATH
from src.models.event import SecurityEvent
from src.data.database import save_event


FAILED_KEYWORDS = [
    "failed password",
    "authentication failure",
    "invalid user",
    "failed login",
]

BRUTE_FORCE_THRESHOLD = 3

# Recent failed-login IPs
failed_attempts = Counter()

# Prevent duplicate brute-force alerts
alerted_ips = set()

# Keep recent log lines for correlation
recent_logs = deque(maxlen=50)


def extract_ip(log_line):
    """
    Extract IPv4 address from a log line.
    """
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_line)

    if match:
        return match.group(0)

    return "N/A"


def is_failed_login(log_line):
    """
    Check whether the log line represents a failed login.
    """
    lower_line = log_line.lower()

    return any(
        keyword in lower_line
        for keyword in FAILED_KEYWORDS
    )


def create_security_event(log_line, event_type, severity, ip):
    """
    Create and save a CloudSentinel security event.
    """

    event = SecurityEvent(
        timestamp=datetime.now(),
        event_type=event_type,
        severity=severity,
        message=log_line,
        source="auth.log",
        ip_address=ip,
    )

    save_event(event)

    return event


def process_log_line(log_line):
    """
    Analyze one newly detected log entry.
    """

    global failed_attempts

    log_line = log_line.strip()

    if not log_line:
        return

    recent_logs.append(log_line)

    lower_line = log_line.lower()

    # -------------------------------------------------
    # Ignore normal sudo session activity
    # -------------------------------------------------

    if "sudo:" in lower_line:

        if (
            "session opened" in lower_line
            or "session closed" in lower_line
        ):
            return

    # -------------------------------------------------
    # Check failed login
    # -------------------------------------------------

    if not is_failed_login(log_line):
        return

    ip = extract_ip(log_line)

    if ip == "N/A":
        return

    # Count failed attempts from this IP
    failed_attempts[ip] += 1

    print(
        f"[DETECTION] Failed login detected | "
        f"IP={ip} | "
        f"Attempts={failed_attempts[ip]}"
    )

    # -------------------------------------------------
    # Brute-force detection
    # -------------------------------------------------

    if (
        failed_attempts[ip] >= BRUTE_FORCE_THRESHOLD
        and ip not in alerted_ips
    ):

        event = create_security_event(
            log_line=log_line,
            event_type="BRUTE_FORCE",
            severity="HIGH",
            ip=ip,
        )

        alerted_ips.add(ip)

        print(
            f"[ALERT] BRUTE FORCE DETECTED | "
            f"IP={ip} | "
            f"{failed_attempts[ip]} failed attempts"
        )

        return

    # -------------------------------------------------
    # Normal suspicious activity
    # -------------------------------------------------

    create_security_event(
        log_line=log_line,
        event_type="SUSPICIOUS_ACTIVITY",
        severity="MEDIUM",
        ip=ip,
    )

    print(
        f"[ALERT] Suspicious activity | "
        f"IP={ip}"
    )


def monitor_log():
    """
    Continuously monitor auth.log for new entries.
    """

    log_path = Path(AUTH_LOG_PATH)

    if not log_path.exists():

        print(
            f"[ERROR] Log file not found: {log_path}"
        )

        return

    print()
    print("=" * 50)
    print("       CloudSentinel Real-Time Monitor")
    print("=" * 50)

    print(f"[INFO] Monitoring: {log_path}")
    print("[INFO] Waiting for new log entries...")
    print("[INFO] Detection engine is ACTIVE")
    print("[INFO] Press Ctrl+C to stop.")
    print()

    try:

        with open(
            log_path,
            "r",
            errors="ignore"
        ) as file:

            # Move to end of file.
            # We only process NEW entries.
            file.seek(0, 2)

            while True:

                line = file.readline()

                if not line:

                    time.sleep(1)
                    continue

                line = line.strip()

                if not line:
                    continue

                print(f"[NEW LOG] {line}")

                # Send new log entry to detection engine
                process_log_line(line)

    except KeyboardInterrupt:

        print()
        print("[INFO] Real-time monitoring stopped.")

    except PermissionError:

        print(
            "[ERROR] Permission denied while reading auth.log."
        )

        print(
            "[INFO] Try running the monitor with sudo."
        )

    except Exception as error:

        print(
            f"[ERROR] Monitoring failed: {error}"
        )


if __name__ == "__main__":
    monitor_log()
