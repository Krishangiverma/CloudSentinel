"""
CloudSentinel Attack Correlation Engine.

Correlates security events into investigation-ready incidents.

Current correlation strategy:

    Same source IP
        +
    Minimum event threshold
        ↓
    Correlated security incident

The engine remains intentionally deterministic so that incident
results are reproducible and easy to test.
"""


DEFAULT_THRESHOLD = 3


# ============================================================
# RISK LEVEL
# ============================================================

def _risk_level_from_score(score):
    """Convert a numeric risk score into a CloudSentinel risk level."""

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 35:
        return "MEDIUM"

    return "LOW"


# ============================================================
# TIMESTAMP SORTING
# ============================================================

def _timestamp_key(event):
    """
    Return a sortable representation of an event timestamp.

    ISO-8601 strings sort correctly in the common CloudSentinel
    timestamp format. String conversion also keeps this function
    safe for datetime-like values.
    """

    timestamp = event.get("timestamp")

    if timestamp is None:
        return ""

    return str(timestamp)


# ============================================================
# ATTACK PATTERN DETECTION
# ============================================================

def _detect_attack_pattern(events):
    """
    Infer a high-level attack pattern from correlated event types.

    This is deterministic rule-based correlation, not ML.
    """

    event_types = {
        str(event.get("event_type", "UNKNOWN")).upper()
        for event in events
    }

    if "BRUTE_FORCE" in event_types or "BRUTE FORCE" in event_types:
        return "BRUTE_FORCE_ACTIVITY"

    if "MALWARE" in event_types:
        return "MALWARE_ACTIVITY"

    if (
        "PORT_SCAN" in event_types
        or "PORT SCAN" in event_types
    ):
        return "RECONNAISSANCE_ACTIVITY"

    if (
        "UNAUTHORIZED_ACCESS" in event_types
        or "UNAUTHORIZED ACCESS" in event_types
        or "INTRUSION" in event_types
    ):
        return "INTRUSION_ACTIVITY"

    if "SUSPICIOUS_LOGIN" in event_types:
        return "SUSPICIOUS_LOGIN_ACTIVITY"

    return "MULTI_EVENT_ACTIVITY"


# ============================================================
# INCIDENT BUILDER
# ============================================================

def _build_incident(incident_id, ip_address, events):
    """
    Build one investigation-ready incident.
    """

    ordered_events = sorted(
        events,
        key=_timestamp_key
    )

    risk_scores = [
        event.get("risk_score", 0) or 0
        for event in ordered_events
    ]

    max_risk = max(risk_scores) if risk_scores else 0

    event_types = {}

    for event in ordered_events:

        event_type = str(
            event.get(
                "event_type",
                "UNKNOWN"
            )
        ).upper()

        event_types[event_type] = (
            event_types.get(event_type, 0) + 1
        )

    return {
        "incident_id": incident_id,
        "ip_address": ip_address,
        "event_count": len(ordered_events),
        "event_types": event_types,
        "attack_pattern": _detect_attack_pattern(
            ordered_events
        ),
        "first_seen": (
            ordered_events[0].get("timestamp")
            if ordered_events
            else None
        ),
        "last_seen": (
            ordered_events[-1].get("timestamp")
            if ordered_events
            else None
        ),
        "max_risk_score": max_risk,
        "risk_level": _risk_level_from_score(
            max_risk
        ),
        "status": "OPEN",
        "events": ordered_events,
    }


# ============================================================
# CORRELATE EVENTS
# ============================================================

def correlate_events(events, threshold=DEFAULT_THRESHOLD):
    """
    Correlate security events by source IP.

    Events from the same valid source IP are grouped together.
    Groups meeting the threshold become investigation-ready
    incidents.

    Args:
        events: Iterable of event dictionaries.
        threshold: Minimum number of events required.

    Returns:
        List of incident dictionaries.
    """

    if threshold < 1:
        raise ValueError(
            "Correlation threshold must be at least 1."
        )

    ip_groups = {}

    for event in events:

        ip_address = event.get(
            "ip_address",
            "UNKNOWN"
        )

        if ip_address in (
            None,
            "",
            "UNKNOWN",
            "N/A",
        ):
            continue

        ip_address = str(ip_address)

        ip_groups.setdefault(
            ip_address,
            []
        ).append(event)

    incidents = []

    # Sorting makes incident IDs deterministic.
    for index, ip_address in enumerate(
        sorted(ip_groups),
        start=1
    ):

        ip_events = ip_groups[ip_address]

        if len(ip_events) < threshold:
            continue

        incident_id = f"INC-{index:04d}"

        incidents.append(
            _build_incident(
                incident_id,
                ip_address,
                ip_events
            )
        )

    return incidents
