"""
CloudSentinel Threat Intelligence Risk Analyzer.

Converts locally enriched IOC intelligence into a deterministic
risk contribution.

This module does not contact external threat-intelligence
providers. It only evaluates the threat-intelligence data
already attached to a CloudSentinel event.
"""


# ============================================================
# RISK BONUSES
# ============================================================

VERDICT_BONUSES = {
    "malicious": 30,
    "suspicious": 20,
    "unknown": 0,
    "non_public": 0,
}


CONTEXT_BONUSES = {
    "public": 5,
    "domain": 5,
    "file_hash": 5,
    "private": 0,
    "loopback": 0,
    "reserved": 0,
    "unspecified": 0,
    "unknown": 0,
}


# ============================================================
# SINGLE IOC RISK
# ============================================================

def calculate_ioc_risk(ioc):
    """
    Calculate the risk contribution of one enriched IOC.

    Returns an integer from 0 to 100.
    """

    if not isinstance(ioc, dict):
        return 0

    verdict = str(
        ioc.get("verdict", "unknown")
    ).lower()

    context = str(
        ioc.get("context", "unknown")
    ).lower()

    verdict_bonus = VERDICT_BONUSES.get(
        verdict,
        0,
    )

    context_bonus = CONTEXT_BONUSES.get(
        context,
        0,
    )

    return min(
        verdict_bonus + context_bonus,
        100,
    )


# ============================================================
# THREAT INTELLIGENCE RISK
# ============================================================

def calculate_threat_intel_risk(threat_intel):
    """
    Calculate the total threat-intelligence risk contribution.

    The highest individual IOC contribution is used rather than
    blindly summing every IOC. This prevents duplicate IOCs from
    artificially inflating the risk score.

    Invalid IOC entries are ignored.

    Returns:

        {
            "threat_intel_score": int,
            "threat_intel_level": str,
            "ioc_count": int
        }
    """

    if not isinstance(threat_intel, dict):
        return {
            "threat_intel_score": 0,
            "threat_intel_level": "LOW",
            "ioc_count": 0,
        }

    items = threat_intel.get(
        "items",
        [],
    )

    if not isinstance(items, list):
        items = []

    # --------------------------------------------------------
    # Keep only valid IOC dictionaries.
    # --------------------------------------------------------

    valid_items = [
        ioc
        for ioc in items
        if isinstance(ioc, dict)
    ]

    scores = [
        calculate_ioc_risk(ioc)
        for ioc in valid_items
    ]

    if not scores:
        score = 0
    else:
        score = max(scores)

    if score >= 30:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "threat_intel_score": score,
        "threat_intel_level": level,
        "ioc_count": len(valid_items),
    }


# ============================================================
# EVENT THREAT INTELLIGENCE RISK
# ============================================================

def analyze_threat_intel_risk(event):
    """
    Analyze threat-intelligence risk from a CloudSentinel event.

    The event is not modified.
    """

    if not isinstance(event, dict):
        return {
            "threat_intel_score": 0,
            "threat_intel_level": "LOW",
            "ioc_count": 0,
        }

    return calculate_threat_intel_risk(
        event.get(
            "threat_intel",
            {},
        )
    )
