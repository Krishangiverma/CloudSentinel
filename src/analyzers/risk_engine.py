"""
CloudSentinel Risk Engine

Calculates a 0-100 risk score for security events.
"""

SEVERITY_SCORES = {
    "LOW": 20,
    "MEDIUM": 45,
    "HIGH": 70,
    "CRITICAL": 90,
}

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


def calculate_risk_score(event):
    """
    Calculate a risk score from 0 to 100.

    Risk is based on:
    - event severity
    - event type
    """

    severity = str(event.get("severity", "LOW")).upper()
    event_type = str(event.get("event_type", "")).upper()

    base_score = SEVERITY_SCORES.get(severity, 20)
    event_bonus = EVENT_TYPE_BONUS.get(event_type, 0)

    risk_score = min(base_score + event_bonus, 100)

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
    }


def analyze_event_risk(event):
    """
    Return the original event enriched with risk information.
    """

    result = dict(event)
    risk = calculate_risk_score(event)

    result["risk_score"] = risk["risk_score"]
    result["risk_level"] = risk["risk_level"]

    return result
