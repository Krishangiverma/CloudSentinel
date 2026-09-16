"""
CloudSentinel MITRE ATT&CK event mapper.

Day 48:
    Connects detected CloudSentinel events to the
    existing detection-to-MITRE registry.

This module intentionally does not modify the canonical
SecurityEvent model. MITRE enrichment is returned as a
separate structure so existing event processing remains
backward compatible.
"""

from typing import Any, Dict, List

from src.mitre.registry import (
    map_detection_to_mitre,
)


# ============================================================
# SINGLE EVENT MAPPING
# ============================================================

def map_event_to_mitre(
    event: Dict[str, Any],
    matched_rule,
) -> Dict[str, Any]:
    """
    Map one detected event to its MITRE ATT&CK context.

    Parameters
    ----------
    event:
        Event dictionary evaluated by the RuleEngine.

    matched_rule:
        DetectionRule that matched the event.

    Returns
    -------
    dict
        MITRE enrichment information.
    """

    if matched_rule is None:
        raise ValueError(
            "matched_rule cannot be None"
        )

    mapping = map_detection_to_mitre(
        matched_rule
    )

    return {
        "rule_id": matched_rule.rule_id,
        "rule_name": matched_rule.name,
        "event_type": matched_rule.event_type,
        "category": matched_rule.category,
        "severity": matched_rule.severity,
        "mitre": mapping.to_dict(),
        "event": {
            "event_type": event.get(
                "event_type",
                "UNKNOWN",
            ),
            "message": event.get(
                "message",
                "",
            ),
            "source": event.get(
                "source",
                "UNKNOWN",
            ),
            "ip": event.get(
                "ip",
                event.get(
                    "ip_address",
                    "N/A",
                ),
            ),
        },
    }


# ============================================================
# MULTIPLE MATCHES
# ============================================================

def map_event_matches_to_mitre(
    event: Dict[str, Any],
    matched_rules: List[Any],
) -> List[Dict[str, Any]]:
    """
    Map one event against multiple matched detection rules.

    Rules without valid MITRE metadata are skipped only if
    the mapping itself raises a ValueError.
    """

    results = []

    for rule in matched_rules:

        try:
            result = map_event_to_mitre(
                event,
                rule,
            )

        except ValueError:
            continue

        results.append(result)

    return results


# ============================================================
# SIMPLE LOOKUP
# ============================================================

def get_event_mitre_context(
    event: Dict[str, Any],
    matched_rule,
) -> Dict[str, Any]:
    """
    Convenience wrapper for retrieving MITRE context
    for one event/rule pair.
    """

    return map_event_to_mitre(
        event,
        matched_rule,
    )
