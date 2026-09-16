"""
CloudSentinel Threat Intelligence Risk Analyzer.

Calculates transparent risk contributions from enriched IOC data.
"""


# ============================================================
# REPUTATION ADJUSTMENT
# ============================================================

def calculate_reputation_adjustment(
    reputation
):
    """
    Convert normalized provider reputation into
    a bounded risk adjustment.

    Reputation scale:

        0-24   -> 5
        25-49  -> 10
        50-74  -> 15
        75-89  -> 20
        90+    -> 25

    Invalid or missing reputation returns 0.
    """

    if reputation is None:
        return 0

    try:
        reputation = float(
            reputation
        )

    except (
        TypeError,
        ValueError,
    ):
        return 0

    if reputation <= 0:
        return 0

    if reputation < 25:
        return 5

    if reputation < 50:
        return 10

    if reputation < 75:
        return 15

    if reputation < 90:
        return 20

    return 25


# ============================================================
# VERDICT BONUSES
# ============================================================

VERDICT_BONUSES = {
    "malicious": 30,
    "suspicious": 20,
    "unknown": 0,
    "non_public": 0,
}


# ============================================================
# CONTEXT BONUSES
# ============================================================

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
# IOC RISK BREAKDOWN
# ============================================================

def calculate_ioc_risk_breakdown(
    ioc
):
    """
    Calculate transparent risk contribution
    for a single IOC.

    Returns:

        {
            "verdict_bonus": int,
            "context_bonus": int,
            "reputation_adjustment": int,
            "total": int
        }
    """

    if not isinstance(
        ioc,
        dict,
    ):
        return {
            "verdict_bonus": 0,
            "context_bonus": 0,
            "reputation_adjustment": 0,
            "total": 0,
        }

    verdict = str(
        ioc.get(
            "verdict",
            "unknown",
        )
    ).lower()

    context = str(
        ioc.get(
            "context",
            "unknown",
        )
    ).lower()

    verdict_bonus = VERDICT_BONUSES.get(
        verdict,
        0,
    )

    context_bonus = CONTEXT_BONUSES.get(
        context,
        0,
    )

    reputation_adjustment = (
        calculate_reputation_adjustment(
            ioc.get(
                "reputation"
            )
        )
    )

    total = min(
        verdict_bonus
        + context_bonus
        + reputation_adjustment,
        100,
    )

    return {
        "verdict_bonus": verdict_bonus,
        "context_bonus": context_bonus,
        "reputation_adjustment": reputation_adjustment,
        "total": total,
    }


# ============================================================
# SINGLE IOC RISK
# ============================================================

def calculate_ioc_risk(
    ioc
):
    """
    Calculate risk score for a single IOC.

    The score is capped at 100.
    """

    breakdown = calculate_ioc_risk_breakdown(
        ioc
    )

    return breakdown["total"]


# ============================================================
# THREAT INTEL RISK
# ============================================================

def calculate_threat_intel_risk(
    threat_intel
):
    """
    Calculate the total threat-intelligence
    risk contribution.

    The highest individual IOC contribution is used
    rather than blindly summing every IOC.

    This prevents duplicate IOCs from artificially
    inflating the risk score.

    Reputation is incorporated as a bounded,
    transparent adjustment.

    Invalid IOC entries are ignored.

    Empty or invalid threat-intelligence collections
    preserve the original three-field result shape.
    """

    # --------------------------------------------------------
    # Invalid threat-intel container
    # --------------------------------------------------------

    if not isinstance(
        threat_intel,
        dict,
    ):
        return {
            "threat_intel_score": 0,
            "threat_intel_level": "LOW",
            "ioc_count": 0,
        }

    # --------------------------------------------------------
    # IOC items
    # --------------------------------------------------------

    items = threat_intel.get(
        "items",
        [],
    )

    if not isinstance(
        items,
        list,
    ):
        items = []

    # --------------------------------------------------------
    # Keep only valid IOC dictionaries
    # --------------------------------------------------------

    valid_items = [
        ioc
        for ioc in items
        if isinstance(
            ioc,
            dict,
        )
    ]

    # --------------------------------------------------------
    # Calculate individual IOC breakdowns
    # --------------------------------------------------------

    breakdowns = [
        calculate_ioc_risk_breakdown(
            ioc
        )
        for ioc in valid_items
    ]

    # --------------------------------------------------------
    # No valid IOC
    #
    # Preserve old API result shape for compatibility.
    # --------------------------------------------------------

    if not breakdowns:
        return {
            "threat_intel_score": 0,
            "threat_intel_level": "LOW",
            "ioc_count": 0,
        }

    # --------------------------------------------------------
    # Select highest-risk IOC
    # --------------------------------------------------------

    selected = max(
        breakdowns,
        key=lambda item: item["total"],
    )

    score = selected[
        "total"
    ]

    reputation_adjustment = selected[
        "reputation_adjustment"
    ]

    # --------------------------------------------------------
    # Threat-intel risk level
    # --------------------------------------------------------

    if score >= 30:
        level = "HIGH"

    elif score >= 15:
        level = "MEDIUM"

    else:
        level = "LOW"

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "threat_intel_score": score,
        "threat_intel_level": level,
        "ioc_count": len(
            valid_items
        ),
        "reputation_adjustment": reputation_adjustment,
    }


# ============================================================
# EVENT LEVEL THREAT INTEL ANALYSIS
# ============================================================

def analyze_threat_intel_risk(
    event
):
    """
    Analyze threat-intelligence risk
    from a CloudSentinel event.

    Events without threat-intelligence data
    preserve the original result shape.
    """

    if not isinstance(
        event,
        dict,
    ):
        return {
            "threat_intel_score": 0,
            "threat_intel_level": "LOW",
            "ioc_count": 0,
        }

    threat_intel = event.get(
        "threat_intel"
    )

    if not threat_intel:
        return {
            "threat_intel_score": 0,
            "threat_intel_level": "LOW",
            "ioc_count": 0,
        }

    return calculate_threat_intel_risk(
        threat_intel
    )
