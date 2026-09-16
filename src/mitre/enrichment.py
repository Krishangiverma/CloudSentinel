"""
CloudSentinel MITRE ATT&CK enrichment service.

Day 48:
    Provides a standalone enrichment layer that connects
    detection results to the existing MITRE ATT&CK registry.

The service does not modify the SecurityEvent model or the
RuleEngine.
"""

from typing import Any, Dict

from src.mitre.registry import map_detection_to_mitre


def enrich_detection_with_mitre(
    detection: Dict[str, Any],
    matched_rule,
) -> Dict[str, Any]:
    """
    Add MITRE ATT&CK context to an existing detection.

    The original detection fields are preserved.
    """

    if matched_rule is None:
        raise ValueError(
            "matched_rule cannot be None"
        )

    enriched = dict(detection)

    mapping = map_detection_to_mitre(
        matched_rule
    )

    enriched["mitre"] = mapping.to_dict()

    return enriched


def has_mitre_enrichment(
    detection: Dict[str, Any],
) -> bool:
    """
    Return True when a detection contains valid MITRE
    enrichment.
    """

    mitre = detection.get(
        "mitre"
    )

    if not isinstance(mitre, dict):
        return False

    return bool(
        mitre.get("technique_id")
    )
