"""
CloudSentinel Authentication Detection Layer.

Day 38:
    Authentication-focused detections.

Supported detections:
    - Failed login
    - Brute force
    - Password spraying
    - Suspicious login
"""

from collections import defaultdict
from typing import Any


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_BRUTE_FORCE_THRESHOLD = 3
DEFAULT_PASSWORD_SPRAY_THRESHOLD = 3

FAILED_LOGIN_KEYWORDS = (
    "failed password",
    "authentication failure",
    "failed login",
)

SUCCESSFUL_LOGIN_KEYWORDS = (
    "accepted password",
    "accepted publickey",
    "successful login",
)


# ============================================================
# HELPERS
# ============================================================

def _get_message(entry: Any) -> str:
    """
    Extract message text from a string or dictionary event.
    """

    if isinstance(entry, dict):
        return str(
            entry.get(
                "message",
                "",
            )
        )

    return str(entry)


def _get_ip(entry: Any) -> str | None:
    """
    Extract source IP from an event.
    """

    if isinstance(entry, dict):

        ip = entry.get("ip")

        if ip and ip != "N/A":
            return str(ip)

    return None


def _get_username(entry: Any) -> str | None:
    """
    Extract username from common authentication messages.

    Supported examples:

        Failed password for user alice from 10.0.0.1
        Failed password for invalid user admin from 10.0.0.1
        Accepted password for alice from 10.0.0.1
    """

    message = _get_message(entry)

    words = message.split()

    for index, word in enumerate(words):

        if word.lower() != "for":
            continue

        # ----------------------------------------------------
        # Format:
        #     for invalid user admin
        # ----------------------------------------------------

        if (
            index + 3 < len(words)
            and words[index + 1].lower() == "invalid"
            and words[index + 2].lower() == "user"
        ):
            return words[index + 3]

        # ----------------------------------------------------
        # Format:
        #     for user alice
        # ----------------------------------------------------

        if (
            index + 2 < len(words)
            and words[index + 1].lower() == "user"
        ):
            return words[index + 2]

        # ----------------------------------------------------
        # Format:
        #     for alice
        # ----------------------------------------------------

        if index + 1 < len(words):
            return words[index + 1]

    return None


def _is_failed_login(entry: Any) -> bool:
    """
    Determine whether an entry represents a failed login.
    """

    message = _get_message(entry).lower()

    return any(
        keyword in message
        for keyword in FAILED_LOGIN_KEYWORDS
    )


def _is_successful_login(entry: Any) -> bool:
    """
    Determine whether an entry represents a successful login.
    """

    message = _get_message(entry).lower()

    return any(
        keyword in message
        for keyword in SUCCESSFUL_LOGIN_KEYWORDS
    )


# ============================================================
# FAILED LOGIN DETECTION
# ============================================================

def detect_failed_logins(entries):
    """
    Detect individual failed authentication attempts.
    """

    detections = []

    for entry in entries:

        if not _is_failed_login(entry):
            continue

        detections.append(
            {
                "event_type": "FAILED_LOGIN",
                "severity": "HIGH",
                "message": _get_message(entry),
                "source": (
                    entry.get(
                        "source",
                        "unknown",
                    )
                    if isinstance(entry, dict)
                    else "unknown"
                ),
                "ip": _get_ip(entry) or "N/A",
                "username": _get_username(entry),
            }
        )

    return detections


# ============================================================
# BRUTE FORCE DETECTION
# ============================================================

def detect_brute_force(
    entries,
    threshold=DEFAULT_BRUTE_FORCE_THRESHOLD,
):
    """
    Detect repeated failed authentication attempts
    from the same source IP.
    """

    attempts_by_ip = defaultdict(list)

    for entry in entries:

        if not _is_failed_login(entry):
            continue

        ip = _get_ip(entry)

        if not ip:
            continue

        attempts_by_ip[ip].append(entry)

    detections = []

    for ip, attempts in attempts_by_ip.items():

        if len(attempts) < threshold:
            continue

        detections.append(
            {
                "event_type": "BRUTE_FORCE",
                "severity": "HIGH",
                "message": (
                    f"Brute-force authentication attack "
                    f"detected from {ip}: "
                    f"{len(attempts)} failed attempts"
                ),
                "source": (
                    "CloudSentinel "
                    "Authentication Detector"
                ),
                "ip": ip,
                "attempt_count": len(attempts),
                "threshold": threshold,
            }
        )

    return detections


# ============================================================
# PASSWORD SPRAYING DETECTION
# ============================================================

def detect_password_spraying(
    entries,
    threshold=DEFAULT_PASSWORD_SPRAY_THRESHOLD,
):
    """
    Detect one source IP attempting authentication
    against multiple different usernames.

    Password spraying:

        one source IP
        +
        multiple usernames
        +
        authentication failures
    """

    users_by_ip = defaultdict(set)
    entries_by_ip = defaultdict(list)

    for entry in entries:

        if not _is_failed_login(entry):
            continue

        ip = _get_ip(entry)
        username = _get_username(entry)

        if not ip or not username:
            continue

        users_by_ip[ip].add(
            username
        )

        entries_by_ip[ip].append(
            entry
        )

    detections = []

    for ip, usernames in users_by_ip.items():

        if len(usernames) < threshold:
            continue

        detections.append(
            {
                "event_type": "PASSWORD_SPRAYING",
                "severity": "HIGH",
                "message": (
                    f"Password spraying detected from "
                    f"{ip}: {len(usernames)} usernames targeted"
                ),
                "source": (
                    "CloudSentinel "
                    "Authentication Detector"
                ),
                "ip": ip,
                "username_count": len(usernames),
                "usernames": sorted(usernames),
                "threshold": threshold,
                "attempt_count": len(
                    entries_by_ip[ip]
                ),
            }
        )

    return detections


# ============================================================
# SUSPICIOUS LOGIN DETECTION
# ============================================================

def detect_suspicious_logins(entries):
    """
    Detect successful logins from an IP that previously
    generated authentication failures in the same event set.

    This is a correlation signal and does not by itself
    establish malicious activity.
    """

    failed_ips = set()

    for entry in entries:

        if not _is_failed_login(entry):
            continue

        ip = _get_ip(entry)

        if ip:
            failed_ips.add(ip)

    detections = []

    for entry in entries:

        if not _is_successful_login(entry):
            continue

        ip = _get_ip(entry)

        if not ip or ip not in failed_ips:
            continue

        detections.append(
            {
                "event_type": "SUSPICIOUS_LOGIN",
                "severity": "HIGH",
                "message": (
                    f"Successful login from {ip} "
                    f"after previous authentication failures"
                ),
                "source": (
                    entry.get(
                        "source",
                        "unknown",
                    )
                    if isinstance(entry, dict)
                    else "unknown"
                ),
                "ip": ip,
                "username": _get_username(entry),
            }
        )

    return detections


# ============================================================
# COMPLETE AUTHENTICATION ANALYSIS
# ============================================================

def analyze_authentication(
    entries,
    brute_force_threshold=DEFAULT_BRUTE_FORCE_THRESHOLD,
    password_spray_threshold=DEFAULT_PASSWORD_SPRAY_THRESHOLD,
):
    """
    Run all Day 38 authentication detections.
    """

    if not entries:
        return []

    detections = []

    detections.extend(
        detect_failed_logins(entries)
    )

    detections.extend(
        detect_brute_force(
            entries,
            threshold=brute_force_threshold,
        )
    )

    detections.extend(
        detect_password_spraying(
            entries,
            threshold=password_spray_threshold,
        )
    )

    detections.extend(
        detect_suspicious_logins(entries)
    )

    return detections

