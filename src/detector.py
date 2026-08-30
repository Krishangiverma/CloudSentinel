import re
from collections import defaultdict
from datetime import datetime


def extract_ip(log_line):
    """
    Extract an IPv4 address from a log line or event dictionary.
    """

    if isinstance(log_line, dict):
        log_line = log_line.get("message", "")

    if not isinstance(log_line, str):
        return None

    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_line)

    if match:
        return match.group(0)

    return None


def _get_message(log_entry):
    """
    Convert both old string-format logs and new dictionary-format
    logs into a single message string.
    """

    if isinstance(log_entry, dict):
        return str(log_entry.get("message", ""))

    return str(log_entry)


def _get_source(log_entry):
    """
    Get log source from dictionary.
    """

    if isinstance(log_entry, dict):
        return log_entry.get("source", "unknown")

    return "unknown"


def _classify_event(message):
    """
    Classify an individual security-related log message.
    """

    text = message.lower()

    # SSH failed login
    if "failed password" in text:
        return "SUSPICIOUS_ACTIVITY", "MEDIUM"

    # Invalid SSH user
    if "invalid user" in text:
        return "SUSPICIOUS_ACTIVITY", "MEDIUM"

    # Authentication failure
    if "authentication failure" in text:
        return "SUSPICIOUS_ACTIVITY", "MEDIUM"

    # Brute-force related keywords
    if "brute force" in text:
        return "BRUTE_FORCE", "HIGH"

    # sudo activity
    if "sudo:" in text or "sudo " in text:
        return "SUDO_ACTIVITY", "MEDIUM"

    # System/security messages
    if "session opened" in text:
        return "SECURITY_LOG", "LOW"

    if "session closed" in text:
        return "SECURITY_LOG", "LOW"

    if "cron" in text:
        return "SECURITY_LOG", "LOW"

    return None, None


def _detect_brute_force(log_entries):
    """
    Detect repeated failed login attempts from the same IP.

    Current threshold:
        3 or more failed attempts = BRUTE_FORCE / HIGH
    """

    failed_attempts = defaultdict(list)

    for entry in log_entries:

        message = _get_message(entry)
        ip = extract_ip(entry)

        if not ip:
            continue

        text = message.lower()

        if (
            "failed password" in text
            or "authentication failure" in text
            or "invalid user" in text
        ):
            failed_attempts[ip].append(message)

    brute_force_events = []

    for ip, attempts in failed_attempts.items():

        if len(attempts) >= 3:

            brute_force_events.append(
                {
                    "event_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "message": (
                        f"Brute-force attack detected from {ip}: "
                        f"{len(attempts)} failed attempts"
                    ),
                    "source": "CloudSentinel",
                    "ip": ip,
                }
            )

    return brute_force_events


def detect_suspicious_events(logs):
    """
    Main CloudSentinel detection engine.

    Accepts:
        - list of strings
        - list of dictionaries

    Returns:
        list of normalized security event dictionaries.
    """

    events = []

    if not logs:
        return events

    # ---------------------------------------------------------
    # STEP 1: Analyze individual log entries
    # ---------------------------------------------------------

    for entry in logs:

        message = _get_message(entry)
        source = _get_source(entry)

        if not message:
            continue

        event_type, severity = _classify_event(message)

        if event_type is None:
            continue

        ip = extract_ip(entry)

        event = {
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "source": source,
            "ip": ip if ip else "N/A",
        }

        events.append(event)

    # ---------------------------------------------------------
    # STEP 2: Detect brute-force attacks
    # ---------------------------------------------------------

    brute_force_events = _detect_brute_force(logs)

    events.extend(brute_force_events)

    # ---------------------------------------------------------
    # STEP 3: Remove duplicate brute-force alerts
    # ---------------------------------------------------------

    unique_events = []

    seen = set()

    for event in events:

        key = (
            event.get("event_type"),
            event.get("severity"),
            event.get("message"),
            event.get("ip"),
        )

        if key not in seen:
            seen.add(key)
            unique_events.append(event)

    return unique_events


def analyze_logs(logs):
    """
    Backward-compatible wrapper.

    Some older CloudSentinel code may call analyze_logs().
    """

    return detect_suspicious_events(logs)


def get_event_statistics(events):
    """
    Generate simple statistics from detected security events.
    """

    statistics = {
        "total_events": len(events),
        "high": 0,
        "medium": 0,
        "low": 0,
        "brute_force": 0,
        "suspicious_activity": 0,
        "sudo_activity": 0,
        "security_log": 0,
    }

    for event in events:

        severity = event.get("severity", "").lower()
        event_type = event.get("event_type", "").lower()

        if severity == "high":
            statistics["high"] += 1

        elif severity == "medium":
            statistics["medium"] += 1

        elif severity == "low":
            statistics["low"] += 1

        if event_type == "brute_force":
            statistics["brute_force"] += 1

        elif event_type == "suspicious_activity":
            statistics["suspicious_activity"] += 1

        elif event_type == "sudo_activity":
            statistics["sudo_activity"] += 1

        elif event_type == "security_log":
            statistics["security_log"] += 1

    return statistics
