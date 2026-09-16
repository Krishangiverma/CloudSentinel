"""
CloudSentinel Risk Engine.

Calculates a 0-100 risk score for security events.

Risk is based on:
    - event severity
    - event type
    - threat-intelligence context when available
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

EVENT_TYPE_BONUS = {
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
# RISK CALCULATION
# ============================================================

def calculate_risk_score(event):
    """
    Calculate a risk score from 0 to 100.

    Risk is based on:
        - event severity
        - event type
        - threat intelligence, when available

    Backward compatibility:
        Events without threat-intelligence data use the
        original severity + event-type calculation.
    """

    if not isinstance(event, dict):
        event = {}

    severity = str(
        event.get(
            "severity",
            "LOW",
        )
    ).upper()

    event_type = str(
        event.get(
            "event_type",
            "",
        )
    ).upper()

    # --------------------------------------------------------
    # 1. Base severity score
    # --------------------------------------------------------

    base_score = SEVERITY_SCORES.get(
        severity,
        20,
    )

    # --------------------------------------------------------
    # 2. Event-type bonus
    # --------------------------------------------------------

    event_bonus = EVENT_TYPE_BONUS.get(
        event_type,
        0,
    )

    # --------------------------------------------------------
    # 3. Threat-intelligence contribution
    #
    # Only calculate this when threat intelligence is attached.
    # This preserves the original behavior for older events.
    # --------------------------------------------------------

    threat_intel_score = 0

    if "threat_intel" in event:

        threat_intel = calculate_threat_intel_risk(
            event.get(
                "threat_intel",
                {},
            )
        )

        threat_intel_score = threat_intel[
            "threat_intel_score"
        ]

    # --------------------------------------------------------
    # 4. Final risk score
    # --------------------------------------------------------

    risk_score = min(
        base_score
        + event_bonus
        + threat_intel_score,
        100,
    )

    # --------------------------------------------------------
    # 5. Risk level
    # --------------------------------------------------------

    if risk_score >= 80:
        risk_level = "CRITICAL"

    elif risk_score >= 60:
        risk_level = "HIGH"

    elif risk_score >= 35:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_intel_score": threat_intel_score,
    }


# ============================================================
# EVENT RISK ANALYSIS
# ============================================================

def analyze_event_risk(event):
    """
    Return the original event enriched with risk information.
    """

    result = dict(event)

    risk = calculate_risk_score(
        event
    )

    result["risk_score"] = risk[
        "risk_score"
    ]

    result["risk_level"] = risk[
        "risk_level"
    ]

    result["threat_intel_score"] = risk[
        "threat_intel_score"
    ]

    return result
