"""
CloudSentinel Detection Engine.

Day 37:
    YAML-based detection rule configuration.

Detection rules are loaded from:
    config/rules/detection_rules.yaml

The legacy public functions are preserved:
    extract_ip()
    detect_suspicious_events()
    analyze_logs()
    detect_suspicious_event()

Multi-event brute-force aggregation remains separate because
it requires counting repeated authentication failures.
"""

import re
from collections import defaultdict
from pathlib import Path

from src.rules.rule_engine import create_engine_from_yaml


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

RULE_CONFIG_PATH = (
    PROJECT_ROOT
    / "config"
    / "rules"
    / "detection_rules.yaml"
)


# ============================================================
# RULE ENGINE
# ============================================================

DETECTION_ENGINE = create_engine_from_yaml(
    str(RULE_CONFIG_PATH)
)


# ============================================================
# HELPERS
# ============================================================

def extract_ip(log_line):
    """
    Extract an IPv4 address from a log line or event dictionary.
    """

    if isinstance(log_line, dict):
        log_line = log_line.get(
            "message",
            "",
        )

    if not isinstance(log_line, str):
        return None

    match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        log_line,
    )

    if match:
        return match.group(0)

    return None


def _get_message(log_entry):
    """
    Convert old string logs and dictionary logs
    into one message string.
    """

    if isinstance(log_entry, dict):
        return str(
            log_entry.get(
                "message",
                "",
            )
        )

    return str(log_entry)


def _get_source(log_entry):
    """
    Get log source from a dictionary entry.
    """

    if isinstance(log_entry, dict):
        return log_entry.get(
            "source",
            "unknown",
        )

    return "unknown"


def _normalize_entry(log_entry):
    """
    Convert a legacy string or dictionary log into the
    normalized event structure consumed by RuleEngine.
    """

    message = _get_message(log_entry)
    source = _get_source(log_entry)

    ip = extract_ip(log_entry)

    return {
        "message": message,
        "source": source,
        "ip": ip if ip else "N/A",
    }


# ============================================================
# BRUTE-FORCE AGGREGATION
# ============================================================

def _detect_brute_force(log_entries):
    """
    Detect repeated authentication failures from the same IP.

    Current compatibility threshold:
        3 or more failures = BRUTE_FORCE / HIGH

    The aggregation logic remains separate from the generic
    RuleEngine because it requires state across multiple events.
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
                        f"Brute-force attack detected from "
                        f"{ip}: {len(attempts)} failed attempts"
                    ),
                    "source": "CloudSentinel",
                    "ip": ip,
                }
            )

    return brute_force_events


# ============================================================
# MAIN DETECTION ENGINE
# ============================================================

def detect_suspicious_events(logs):
    """
    Main CloudSentinel detection engine.

    Accepts:
        - list of strings
        - list of dictionaries

    Returns:
        List of normalized security event dictionaries.

    Individual detections are evaluated through rules loaded
    from YAML.

    Multi-event brute-force correlation remains a separate
    aggregation step.
    """

    events = []

    if not logs:
        return events

    # ---------------------------------------------------------
    # STEP 1: Evaluate individual entries through YAML rules
    # ---------------------------------------------------------

    for entry in logs:

        normalized_entry = _normalize_entry(entry)

        if not normalized_entry["message"]:
            continue

        detections = DETECTION_ENGINE.evaluate(
            normalized_entry
        )

        for detection in detections:

            event = {
                "event_type": detection["event_type"],
                "severity": detection["severity"],
                "message": detection["message"],
                "source": detection["source"],
                "ip": detection["ip"],
            }

            events.append(event)

    # ---------------------------------------------------------
    # STEP 2: Multi-event brute-force detection
    # ---------------------------------------------------------

    brute_force_events = _detect_brute_force(
        logs
    )

    events.extend(
        brute_force_events
    )

    # ---------------------------------------------------------
    # STEP 3: Remove duplicates
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


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

def analyze_logs(logs):
    """
    Backward-compatible wrapper.
    """

    return detect_suspicious_events(
        logs
    )


def detect_suspicious_event(event):
    """
    Legacy singular-event compatibility wrapper.
    """

    detected = detect_suspicious_events(
        [event]
    )

    if detected:
        return detected[0]

    return None
