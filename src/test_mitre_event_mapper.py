"""
Day 48 tests for SecurityEvent -> MITRE enrichment.
"""

from src.mitre.event_mapper import (
    get_event_mitre_context,
    map_event_matches_to_mitre,
    map_event_to_mitre,
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


# ============================================================
# SINGLE EVENT
# ============================================================

def test_event_maps_to_mitre():

    rules = _load_rules()

    rule = _get_rule(
        rules,
        "brute_force",
    )

    event = {
        "event_type": "BRUTE_FORCE",
        "message": (
            "Multiple brute force attempts detected"
        ),
        "source": "CloudSentinel",
        "ip": "192.168.1.100",
    }

    result = map_event_to_mitre(
        event,
        rule,
    )

    assert result["rule_id"] == "AUTH-004"
    assert result["rule_name"] == "brute_force"

    assert result["mitre"]["technique_id"] == "T1110"
    assert result["mitre"]["technique"] == "Brute Force"
    assert result["mitre"]["tactic"] == "Credential Access"

    assert (
        result["event"]["event_type"]
        == "BRUTE_FORCE"
    )

    assert (
        result["event"]["ip"]
        == "192.168.1.100"
    )


# ============================================================
# SUB-TECHNIQUE
# ============================================================

def test_event_maps_to_mitre_subtechnique():

    rules = _load_rules()

    rule = _get_rule(
        rules,
        "sudo_activity",
    )

    event = {
        "event_type": "PRIVILEGE_ACTIVITY",
        "message": "sudo: user executed command",
        "source": "auth.log",
        "ip_address": "10.0.0.5",
    }

    result = map_event_to_mitre(
        event,
        rule,
    )

    assert (
        result["mitre"]["technique_id"]
        == "T1548"
    )

    assert (
        result["mitre"]["subtechnique_id"]
        == "T1548.003"
    )

    assert (
        result["mitre"]["subtechnique"]
        == "Sudo and Sudo Caching"
    )

    assert (
        result["event"]["ip"]
        == "10.0.0.5"
    )


# ============================================================
# MULTIPLE MATCHES
# ============================================================

def test_multiple_rule_matches_are_mapped():

    rules = _load_rules()

    brute_force = _get_rule(
        rules,
        "brute_force",
    )

    authentication_failure = _get_rule(
        rules,
        "authentication_failure",
    )

    event = {
        "event_type": "AUTHENTICATION_FAILURE",
        "message": (
            "Brute force authentication failure"
        ),
        "source": "sshd",
        "ip": "192.168.1.50",
    }

    results = map_event_matches_to_mitre(
        event,
        [
            brute_force,
            authentication_failure,
        ],
    )

    assert len(results) == 2

    technique_ids = {
        item["mitre"]["technique_id"]
        for item in results
    }

    assert technique_ids == {
        "T1110"
    }


# ============================================================
# CONVENIENCE WRAPPER
# ============================================================

def test_get_event_mitre_context():

    rules = _load_rules()

    rule = _get_rule(
        rules,
        "cron_activity",
    )

    event = {
        "event_type": "CRON_ACTIVITY",
        "message": "cron job executed",
        "source": "syslog",
        "ip": "N/A",
    }

    result = get_event_mitre_context(
        event,
        rule,
    )

    assert result["rule_name"] == "cron_activity"
    assert (
        result["mitre"]["technique_id"]
        == "T1053"
    )
    assert (
        result["mitre"]["technique"]
        == "Scheduled Task/Job"
    )


# ============================================================
# INVALID RULE
# ============================================================

def test_none_rule_is_rejected():

    event = {
        "event_type": "TEST",
        "message": "test",
    }

    try:
        map_event_to_mitre(
            event,
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
