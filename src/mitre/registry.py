"""
CloudSentinel MITRE ATT&CK detection mapping registry.

Day 47:
    Maps existing CloudSentinel detection rules to the
    structured MITREMapping model created on Day 46.

The registry deliberately keeps detection-rule loading
separate from MITRE metadata enrichment.
"""

from typing import Any, Dict, List

from src.mitre.mapping import MITREMapping


# ============================================================
# ATT&CK KNOWLEDGE FOR CURRENT DETECTIONS
# ============================================================

MITRE_TECHNIQUE_CATALOG: Dict[str, Dict[str, Any]] = {

    "T1110": {
        "technique": "Brute Force",
        "tactic": "Credential Access",
    },

    "T1078": {
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion",
    },

    "T1548": {
        "technique": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },

    "T1053": {
        "technique": "Scheduled Task/Job",
        "tactic": "Persistence",
    },
}


# ============================================================
# DETECTION EVIDENCE
# ============================================================

DETECTION_EVIDENCE: Dict[str, List[str]] = {

    "ssh_failed_password": [
        "Failed SSH password authentication detected"
    ],

    "ssh_invalid_user": [
        "SSH authentication attempt against an invalid user"
    ],

    "authentication_failure": [
        "Authentication failure event detected"
    ],

    "brute_force": [
        "Explicit brute-force activity indicator detected"
    ],

    "sudo_activity": [
        "Sudo-related privilege activity detected"
    ],

    "session_opened": [
        "User session creation event detected"
    ],

    "session_closed": [
        "User session termination event detected"
    ],

    "cron_activity": [
        "Cron-related security log activity detected"
    ],
}


# ============================================================
# EVIDENCE-AWARE MAPPING CONFIDENCE
# ============================================================

# These scores describe confidence in the rule-to-technique
# association, not the probability that an attack occurred.
# Generic log matches receive more conservative scores.
DEFAULT_CONFIDENCE = 0.70

RULE_MAPPING_CONFIDENCE = {
    "brute_force": 0.90,
    "ssh_failed_password": 0.75,
    "ssh_invalid_user": 0.55,
    "authentication_failure": 0.65,
    "sudo_activity": 0.50,
    "session_opened": 0.40,
    "session_closed": 0.35,
    "cron_activity": 0.45,
}


# Status describes how strongly the rule evidence supports
# the ATT&CK mapping; it does not assert that an attack occurred.
RULE_MAPPING_STATUS = {
    # The current rule matches explicit text; its threshold
    # alone does not prove repeated authentication failures.
    "brute_force": "candidate",
}


# ============================================================
# SUB-TECHNIQUE HELPERS
# ============================================================

def _split_technique_id(
    technique_id: str,
) -> tuple[str, str | None]:
    """
    Split:

        T1110
    into:

        T1110, None

    or:

        T1548.003
    into:

        T1548, T1548.003
    """

    normalized = str(
        technique_id
    ).strip().upper()

    if "." in normalized:
        parent = normalized.split(
            ".",
            1,
        )[0]

        return (
            parent,
            normalized,
        )

    return (
        normalized,
        None,
    )


# ============================================================
# SINGLE RULE MAPPING
# ============================================================

def map_detection_to_mitre(
    rule,
) -> MITREMapping:
    """
    Convert one DetectionRule into a structured
    MITREMapping.
    """

    technique_id = rule.metadata.get(
        "MITRE"
    )

    if not technique_id:
        raise ValueError(
            f"Detection rule '{rule.name}' "
            "does not contain MITRE metadata"
        )

    normalized_id = str(
        technique_id
    ).strip().upper()

    parent_id, subtechnique_id = (
        _split_technique_id(
            normalized_id
        )
    )

    catalog_entry = MITRE_TECHNIQUE_CATALOG.get(
        parent_id
    )

    if catalog_entry is None:
        raise ValueError(
            f"Unknown MITRE technique: "
            f"{normalized_id}"
        )

    evidence = DETECTION_EVIDENCE.get(
        rule.name,
        [
            rule.description
            or f"Detection rule '{rule.name}'"
        ],
    )

    subtechnique_name = None

    if subtechnique_id == "T1548.003":
        subtechnique_name = (
            "Sudo and Sudo Caching"
        )

    return MITREMapping(
        tactic=catalog_entry["tactic"],
        technique_id=parent_id,
        technique=catalog_entry["technique"],
        subtechnique_id=subtechnique_id,
        subtechnique=subtechnique_name,
        evidence=evidence,
        confidence=RULE_MAPPING_CONFIDENCE.get(
            rule.name,
            DEFAULT_CONFIDENCE,
        ),
        mapping_status=RULE_MAPPING_STATUS.get(
            rule.name,
            "candidate",
        ),
    )


# ============================================================
# MAP ALL DETECTIONS
# ============================================================

def build_detection_mitre_mappings(
    rules,
) -> List[Dict[str, Any]]:
    """
    Build API-friendly MITRE mappings for all supplied
    detection rules.
    """

    mappings = []

    for rule in rules:

        mapping = map_detection_to_mitre(
            rule
        )

        mappings.append({
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "category": rule.category,
            "severity": rule.severity,
            "enabled": rule.enabled,
            "mapping": mapping.to_dict(),
        })

    return mappings


# ============================================================
# LOOKUP
# ============================================================

def find_detection_mitre_mapping(
    rules,
    rule_id: str,
) -> Dict[str, Any] | None:
    """
    Find one detection's MITRE mapping by rule ID.
    """

    normalized_rule_id = str(
        rule_id
    ).strip().upper()

    for item in build_detection_mitre_mappings(
        rules
    ):

        if (
            str(item["rule_id"]).upper()
            == normalized_rule_id
        ):
            return item

    return None
