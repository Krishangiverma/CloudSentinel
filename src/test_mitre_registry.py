"""
Day 47 tests for detection-to-MITRE mapping.
"""

from src.mitre.registry import (
    build_detection_mitre_mappings,
    find_detection_mitre_mapping,
    map_detection_to_mitre,
)
from src.rules.rule_loader import (
    load_rules_from_yaml,
)


RULE_FILE = (
    "config/rules/detection_rules.yaml"
)


def _load_rules():
    return load_rules_from_yaml(
        RULE_FILE
    )


# ============================================================
# SINGLE DETECTION
# ============================================================

def test_detection_maps_to_mitre():

    rules = _load_rules()

    rule = next(
        rule
        for rule in rules
        if rule.name == "brute_force"
    )

    mapping = map_detection_to_mitre(
        rule
    )

    assert mapping.technique_id == "T1110"
    assert mapping.technique == "Brute Force"
    assert mapping.tactic == "Credential Access"
    assert mapping.subtechnique_id is None
    assert mapping.confidence == 0.90


# ============================================================
# SUB-TECHNIQUE
# ============================================================

def test_sudo_detection_maps_to_subtechnique():

    rules = _load_rules()

    rule = next(
        rule
        for rule in rules
        if rule.name == "sudo_activity"
    )

    mapping = map_detection_to_mitre(
        rule
    )

    assert mapping.technique_id == "T1548"
    assert mapping.subtechnique_id == "T1548.003"
    assert mapping.subtechnique == (
        "Sudo and Sudo Caching"
    )


# ============================================================
# ALL DETECTIONS
# ============================================================

def test_all_existing_detections_are_mapped():

    rules = _load_rules()

    mappings = build_detection_mitre_mappings(
        rules
    )

    assert len(mappings) == 8

    for item in mappings:

        assert item["rule_id"]
        assert item["rule_name"]
        assert item["mapping"]["tactic"]
        assert item["mapping"]["technique_id"]
        assert item["mapping"]["technique"]
        assert item["mapping"]["evidence"]
        assert 0.0 <= (
            item["mapping"]["confidence"]
        ) <= 1.0


# ============================================================
# LOOKUP
# ============================================================

def test_detection_mapping_lookup():

    rules = _load_rules()

    result = find_detection_mitre_mapping(
        rules,
        "PRIV-001",
    )

    assert result is not None
    assert result["rule_name"] == "sudo_activity"
    assert (
        result["mapping"]["subtechnique_id"]
        == "T1548.003"
    )


def test_unknown_detection_returns_none():

    rules = _load_rules()

    result = find_detection_mitre_mapping(
        rules,
        "DOES-NOT-EXIST",
    )

    assert result is None


# ============================================================
# DAY 99: EVIDENCE-AWARE MAPPING REGRESSION TESTS
# ============================================================

def test_mapping_confidence_reflects_rule_evidence():
    rules = _load_rules()

    brute_force = next(
        rule for rule in rules
        if rule.name == "brute_force"
    )
    sudo_activity = next(
        rule for rule in rules
        if rule.name == "sudo_activity"
    )

    brute_mapping = map_detection_to_mitre(brute_force)
    sudo_mapping = map_detection_to_mitre(sudo_activity)

    # Explicit brute-force evidence should have higher
    # mapping confidence than a generic sudo log match.
    assert brute_mapping.confidence > sudo_mapping.confidence


def test_mapping_evidence_is_nonempty_and_rule_specific():
    rules = _load_rules()

    for rule in rules:
        mapping = map_detection_to_mitre(rule)

        assert mapping.evidence
        assert all(
            isinstance(item, str) and item.strip()
            for item in mapping.evidence
        )


# ============================================================
# DAY 100: MITRE SEMANTIC ACCURACY AUDIT
# ============================================================

def test_day100_flags_mappings_that_need_semantic_review():
    rules = _load_rules()
    mappings = {
        rule.name: map_detection_to_mitre(rule)
        for rule in rules
    }

    # These current mappings need review because the observed
    # log event alone does not establish the ATT&CK behavior.
    assert mappings["ssh_invalid_user"].technique_id == "T1078"
    assert mappings["session_opened"].technique_id == "T1078"
    assert mappings["session_closed"].technique_id == "T1078"
    assert mappings["sudo_activity"].subtechnique_id == "T1548.003"
    assert mappings["cron_activity"].technique_id == "T1053"


# ============================================================
# DAY 100: EVIDENCE-AWARE MAPPING STATUS
# ============================================================

def test_day100_brute_force_mapping_status_remains_candidate():
    rules = _load_rules()
    rule = next(r for r in rules if r.name == "brute_force")

    mapping = map_detection_to_mitre(rule)

    assert mapping.mapping_status == "candidate"
    assert mapping.to_dict()["mapping_status"] == "candidate"


def test_day100_generic_activity_mappings_remain_candidates():
    rules = _load_rules()
    rules_by_name = {rule.name: rule for rule in rules}

    generic_rule_names = (
        "ssh_invalid_user",
        "sudo_activity",
        "session_opened",
        "session_closed",
        "cron_activity",
    )

    for name in generic_rule_names:
        mapping = map_detection_to_mitre(rules_by_name[name])
        assert mapping.mapping_status == "candidate", name
