"""
CloudSentinel Risk Engine.

Calculates a transparent 0-100 risk score for security events.
"""

from src.analyzers.threat_intel_risk import (
    calculate_threat_intel_risk,
)


# ============================================================
# SEVERITY SCORES
# ============================================================

SEVERITY_SCORES = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90,
}


# ============================================================
# EVENT TYPE BONUSES
# ============================================================

EVENT_BONUSES = {
    "BRUTE_FORCE": 10,
    "BRUTE FORCE": 10,

    "UNAUTHORIZED_ACCESS": 15,
    "UNAUTHORIZED ACCESS": 15,

    "MALWARE": 20,

    "INTRUSION": 20,

    "PORT_SCAN": 15,
    "PORT SCAN": 15,

    "SUSPICIOUS_LOGIN": 10,
    "SUSPICIOUS LOGIN": 10,
}


# ============================================================
# RISK LEVEL
# ============================================================

def _get_risk_level(
    risk_score
):
    """
    Convert a numeric risk score into
    a CloudSentinel risk level.
    """

    if risk_score >= 80:
        return "CRITICAL"

    if risk_score >= 60:
        return "HIGH"

    if risk_score >= 35:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    event
):
    """
    Calculate the final 0-100 risk score.

    Formula:

        Base Severity
        + Event Type Bonus
        + Threat Intelligence Score

    The final score is capped at 100.

    Reputation adjustment is already incorporated
    into the threat-intelligence score.
    """

    # --------------------------------------------------------
    # Preserve existing safe behavior for invalid input.
    #
    # Existing CloudSentinel behavior treats an invalid event
    # as a default LOW-severity event.
    # --------------------------------------------------------

    if not isinstance(
        event,
        dict,
    ):
        return {
            "risk_score": SEVERITY_SCORES["LOW"],
            "risk_level": "LOW",
            "threat_intel_score": 0,
            "reputation_adjustment": 0,
        }

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity = str(
        event.get(
            "severity",
            "LOW",
        )
    ).upper()

    base_score = SEVERITY_SCORES.get(
        severity,
        SEVERITY_SCORES["LOW"],
    )

    # --------------------------------------------------------
    # Event type
    # --------------------------------------------------------

    event_type = str(
        event.get(
            "event_type",
            "",
        )
    ).upper()

    event_bonus = EVENT_BONUSES.get(
        event_type,
        0,
    )

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    threat_intel_score = 0

    reputation_adjustment = 0

    if "threat_intel" in event:

        threat_intel = calculate_threat_intel_risk(
            event.get(
                "threat_intel"
            )
        )

        threat_intel_score = threat_intel.get(
            "threat_intel_score",
            0,
        )

        # Day 57:
        # Reputation adjustment is optional because
        # legacy/empty threat-intel results do not contain
        # this field.
        reputation_adjustment = threat_intel.get(
            "reputation_adjustment",
            0,
        )

    # --------------------------------------------------------
    # Final score
    # --------------------------------------------------------

    risk_score = min(
        base_score
        + event_bonus
        + threat_intel_score,
        100,
    )

    risk_level = _get_risk_level(
        risk_score
    )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_intel_score": threat_intel_score,
        "reputation_adjustment": reputation_adjustment,
    }


# ============================================================
# EVENT RISK ANALYSIS
# ============================================================

def analyze_event_risk(
    event
):
    """
    Analyze an event and return a copy enriched
    with risk information.

    The original event is not modified.
    """

    if not isinstance(
        event,
        dict,
    ):
        return {
            "risk_score": SEVERITY_SCORES["LOW"],
            "risk_level": "LOW",
            "threat_intel_score": 0,
            "reputation_adjustment": 0,
        }

    result = dict(
        event
    )

    risk = calculate_risk_score(
        event
    )

    result.update(
        risk
    )

    return result
