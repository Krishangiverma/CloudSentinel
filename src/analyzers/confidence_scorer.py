"""
Day 65 - Correlated Incident Confidence Scoring.

Confidence is deliberately separate from risk.

Risk answers:
    "How dangerous is this activity?"

Confidence answers:
    "How strongly does the available evidence support that these
     correlated events represent one meaningful incident/attack chain?"

The scorer is deterministic, explainable, and bounded to 0-100.
"""

from datetime import datetime, timezone


# Maximum contribution of each confidence factor.
FACTOR_MAX = {
    "event_evidence": 20,
    "multi_stage_coverage": 25,
    "correlation_relationships": 20,
    "identity_continuity": 15,
    "temporal_coherence": 10,
    "supporting_evidence": 10,
}

TOTAL_MAX_SCORE = sum(FACTOR_MAX.values())


def _parse_timestamp(value):
    """Parse common ISO timestamps safely."""
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed
    except (TypeError, ValueError):
        return None


def _clamp(value, minimum=0, maximum=100):
    """Clamp a numeric value to a safe range."""
    return max(minimum, min(maximum, int(round(value))))


def _confidence_level(score):
    """Convert a 0-100 confidence score into an explainable level."""
    if score >= 85:
        return "VERY_HIGH"

    if score >= 70:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


def _event_evidence_score(event_count):
    """
    Reward sufficient event evidence.

    1 event  -> 4
    2 events -> 8
    ...
    5+ events -> 20
    """
    return min(max(int(event_count), 0), 5) * 4


def _multi_stage_score(attack_chain):
    """
    Score attack-stage coverage.

    A complete four-stage chain receives the full 25 points.
    """
    if not isinstance(attack_chain, dict):
        return 0

    stage_count = attack_chain.get("stage_count", 0) or 0
    stage_count = max(int(stage_count), 0)

    if attack_chain.get("complete_attack_chain"):
        return 25

    return min(stage_count, 4) * 6


def _relationship_score(correlation):
    """Reward multiple independent correlation relationships."""
    if not isinstance(correlation, dict):
        return 0

    relationships = correlation.get("relationships", [])
    if not isinstance(relationships, list):
        return 0

    return min(len(relationships), 4) * 5


def _identity_score(source_ips, users):
    """
    Reward identity continuity.

    Same source identity is strong evidence.
    Same user identity is also strong evidence, especially when
    correlation spans multiple source IPs.
    """
    score = 0

    valid_ips = {
        str(value).strip()
        for value in (source_ips or [])
        if str(value).strip()
    }

    valid_users = {
        str(value).strip()
        for value in (users or [])
        if str(value).strip()
    }

    if valid_ips:
        score += 8

    if valid_users:
        score += 7

    return min(score, 15)


def _temporal_score(events, time_window_seconds):
    """
    Reward temporally coherent evidence.

    A fully valid timeline within the configured correlation window
    receives 10 points. Partial evidence receives proportionally less.
    """
    if not isinstance(events, list) or len(events) < 2:
        return 0

    timestamps = [
        _parse_timestamp(event.get("timestamp"))
        for event in events
        if isinstance(event, dict)
    ]

    if len(timestamps) != len(events) or any(
        timestamp is None for timestamp in timestamps
    ):
        return 0

    timestamps.sort()
    span_seconds = max(
        0.0,
        (timestamps[-1] - timestamps[0]).total_seconds(),
    )

    try:
        window = float(time_window_seconds)
    except (TypeError, ValueError):
        return 0

    if window <= 0:
        return 10 if span_seconds == 0 else 0

    if span_seconds <= window:
        return 10

    # Evidence outside the configured window gets partial credit
    # rather than disappearing completely.
    ratio = max(0.0, 1.0 - ((span_seconds - window) / window))
    return _clamp(ratio * 10, 0, 10)


def _supporting_evidence_score(incident):
    """
    Reward strong supporting security evidence.

    This intentionally uses risk/threat-intel as supporting evidence,
    not as the primary confidence signal.
    """
    score = 0

    max_risk = incident.get("max_risk_score", 0) or 0
    max_threat_intel = incident.get(
        "max_threat_intel_score",
        0,
    ) or 0

    critical_count = incident.get("critical_event_count", 0) or 0
    high_count = incident.get("high_risk_event_count", 0) or 0

    try:
        max_risk = float(max_risk)
    except (TypeError, ValueError):
        max_risk = 0

    try:
        max_threat_intel = float(max_threat_intel)
    except (TypeError, ValueError):
        max_threat_intel = 0

    if max_risk >= 80:
        score += 4
    elif max_risk >= 60:
        score += 3
    elif max_risk >= 40:
        score += 2
    elif max_risk > 0:
        score += 1

    if max_threat_intel >= 50:
        score += 3
    elif max_threat_intel > 0:
        score += 2

    if critical_count:
        score += 2
    elif high_count:
        score += 1

    return min(score, 10)


def calculate_confidence(
    incident,
    time_window_seconds=300,
):
    """
    Calculate deterministic correlated-incident confidence.

    Returns:
        {
            "score": int,
            "level": str,
            "factors": {...},
            "reasons": [...]
        }
    """
    if not isinstance(incident, dict):
        raise TypeError("Incident must be a dictionary.")

    attack_chain = incident.get("attack_chain", {})
    correlation = incident.get("correlation", {})

    event_count = incident.get("event_count", 0) or 0
    source_ips = incident.get("source_ips", [])
    users = incident.get("users", [])
    events = incident.get("events", [])

    event_evidence = _event_evidence_score(event_count)
    multi_stage = _multi_stage_score(attack_chain)
    relationships = _relationship_score(correlation)
    identity = _identity_score(source_ips, users)
    temporal = _temporal_score(events, time_window_seconds)
    supporting = _supporting_evidence_score(incident)

    factors = {
        "event_evidence": event_evidence,
        "multi_stage_coverage": multi_stage,
        "correlation_relationships": relationships,
        "identity_continuity": identity,
        "temporal_coherence": temporal,
        "supporting_evidence": supporting,
    }

    score = _clamp(sum(factors.values()), 0, TOTAL_MAX_SCORE)
    level = _confidence_level(score)

    reasons = []

    if event_evidence >= 12:
        reasons.append(
            "Multiple correlated events provide substantial evidence."
        )
    elif event_evidence > 0:
        reasons.append(
            "The incident has limited event evidence."
        )

    stage_count = (
        attack_chain.get("stage_count", 0)
        if isinstance(attack_chain, dict)
        else 0
    )

    if isinstance(attack_chain, dict) and attack_chain.get(
        "complete_attack_chain"
    ):
        reasons.append(
            "Evidence covers a complete multi-stage attack chain."
        )
    elif stage_count >= 2:
        reasons.append(
            f"Evidence spans {stage_count} attack stages."
        )
    else:
        reasons.append(
            "Limited attack-stage diversity is present."
        )

    relationship_count = (
        len(correlation.get("relationships", []))
        if isinstance(correlation, dict)
        and isinstance(correlation.get("relationships", []), list)
        else 0
    )

    if relationship_count:
        reasons.append(
            f"{relationship_count} explicit event relationships support correlation."
        )
    else:
        reasons.append(
            "No explicit event relationships strengthen the correlation."
        )

    if source_ips:
        reasons.append("Source identity continuity is present.")

    if users:
        reasons.append("User identity continuity is present.")

    if temporal >= 8:
        reasons.append(
            "Events are temporally coherent within the correlation window."
        )
    elif temporal > 0:
        reasons.append(
            "Events show partial temporal coherence."
        )
    else:
        reasons.append(
            "Temporal evidence is limited or incomplete."
        )

    if supporting >= 6:
        reasons.append(
            "Risk, severity, or threat-intelligence evidence strengthens confidence."
        )
    elif supporting > 0:
        reasons.append(
            "Some supporting security evidence is present."
        )
    else:
        reasons.append(
            "Little independent supporting security evidence is present."
        )

    return {
        "score": score,
        "level": level,
        "factors": factors,
        "reasons": reasons,
    }


def score_incident(
    incident,
    time_window_seconds=300,
):
    """Backward-friendly alias for calculate_confidence()."""
    return calculate_confidence(
        incident,
        time_window_seconds=time_window_seconds,
    )
