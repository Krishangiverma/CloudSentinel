"""
Day 48 tests for the standalone MITRE enrichment service.
"""

from src.mitre.enrichment import (
    enrich_detection_with_mitre,
    has_mitre_enrichment,
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


def _get_rule(
    rules,
    rule_name,
):
    return next(
        rule
        for rule in rules
        if rule.name == rule_name
    )


def test_enrich_detection_with_mitre():

    rules = _load_rules()

    rule = _get_rule(
        rules,
        "brute_force",
    )

    detection = {
        "rule_name": "brute_force",
        "rule_id": "AUTH-004",
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Brute-force detected",
        "source": "CloudSentinel",
        "ip": "192.168.1.100",
    }

    enriched = enrich_detection_with_mitre(
        detection,
        rule,
    )

    assert enriched["rule_name"] == "brute_force"
    assert enriched["rule_id"] == "AUTH-004"

    assert enriched["mitre"]["technique_id"] == "T1110"
    assert enriched["mitre"]["technique"] == "Brute Force"
    assert enriched["mitre"]["tactic"] == "Credential Access"


def test_original_detection_fields_are_preserved():

    rules = _load_rules()

    rule = _get_rule(
        rules,
        "sudo_activity",
    )

    detection = {
        "rule_name": "sudo_activity",
        "rule_id": "PRIV-001",
        "event_type": "PRIVILEGE_ACTIVITY",
        "severity": "MEDIUM",
        "message": "sudo activity detected",
        "source": "auth.log",
        "ip": "10.0.0.5",
    }

    enriched = enrich_detection_with_mitre(
        detection,
        rule,
    )

    assert enriched["rule_name"] == "sudo_activity"
    assert enriched["rule_id"] == "PRIV-001"
    assert enriched["event_type"] == "PRIVILEGE_ACTIVITY"
    assert enriched["severity"] == "MEDIUM"
    assert enriched["message"] == "sudo activity detected"
    assert enriched["source"] == "auth.log"
    assert enriched["ip"] == "10.0.0.5"

    assert enriched["mitre"]["technique_id"] == "T1548"
    assert enriched["mitre"]["subtechnique_id"] == "T1548.003"


def test_has_mitre_enrichment():

    detection = {
        "rule_name": "brute_force",
        "mitre": {
            "technique_id": "T1110",
            "technique": "Brute Force",
        },
    }

    assert has_mitre_enrichment(
        detection
    )


def test_missing_mitre_enrichment():

    detection = {
        "rule_name": "unknown",
    }

    assert not has_mitre_enrichment(
        detection
    )


def test_none_rule_is_rejected():

    detection = {
        "rule_name": "brute_force",
    }

    try:
        enrich_detection_with_mitre(
            detection,
            None,
        )
    except ValueError as exc:
        assert (
            str(exc)
            == "matched_rule cannot be None"
        )
    else:
        raise AssertionError(
            "Expected ValueError"
        )
