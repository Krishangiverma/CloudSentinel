"""Day 72 tests for investigation context validation."""

from copy import deepcopy

from src.ai.investigation_context import CONTEXT_SCHEMA_VERSION
from src.ai.investigation_context_validator import (
    validate_investigation_context,
)


def valid_context():
    return {
        "schema_version": CONTEXT_SCHEMA_VERSION,
        "incident": {
            "incident_id": "INC-DAY72-001",
            "attack_pattern": "SSH_BRUTE_FORCE",
            "status": "OPEN",
            "event_count": 1,
            "confidence": None,
            "response_priority": None,
        },
        "risk": {
            "max_score": 75,
            "average_score": 75.0,
            "risk_level": "HIGH",
            "event_scores": [75],
            "level_counts": {
                "CRITICAL": 0,
                "HIGH": 1,
                "MEDIUM": 0,
                "LOW": 0,
            },
            "max_threat_intel_score": 0,
        },
        "events": [{"event_type": "BRUTE_FORCE"}],
        "iocs": {
            "summary": {
                "total_ips": 1,
                "total_domains": 0,
                "total_urls": 0,
                "total_hashes": 0,
                "has_iocs": True,
            },
            "indicators": {
                "ips": ["192.0.2.10"],
                "domains": [],
                "urls": [],
                "hashes": {
                    "md5": [],
                    "sha1": [],
                    "sha256": [],
                },
            },
        },
        "detections": [],
        "mitre_attack": [],
        "attack_chain": {},
        "attack_graph": {
            "nodes": [],
            "edges": [],
        },
        "timeline": {
            "entries": [],
            "relationships": [],
        },
    }


def test_valid_context_has_no_validation_errors():
    assert validate_investigation_context(valid_context()) == []


def test_non_dictionary_context_is_rejected():
    errors = validate_investigation_context(None)

    assert errors == ["context must be a dictionary."]


def test_missing_required_section_is_reported():
    context = valid_context()
    del context["attack_chain"]

    errors = validate_investigation_context(context)

    assert "Missing required section: attack_chain." in errors


def test_unsupported_schema_version_is_reported():
    context = valid_context()
    context["schema_version"] = "99.0"

    errors = validate_investigation_context(context)

    assert any("Unsupported schema_version" in error for error in errors)


def test_invalid_event_type_is_reported():
    context = valid_context()
    context["events"] = ["not-an-event-dictionary"]

    errors = validate_investigation_context(context)

    assert "events[0] must be a dictionary." in errors


def test_invalid_risk_score_type_is_reported():
    context = valid_context()
    context["risk"]["max_score"] = "high"

    errors = validate_investigation_context(context)

    assert "risk.max_score must be numeric." in errors


def test_invalid_graph_structure_is_reported():
    context = valid_context()
    context["attack_graph"]["nodes"] = {}

    errors = validate_investigation_context(context)

    assert "attack_graph.nodes must be a list." in errors


def test_validation_does_not_mutate_context():
    context = valid_context()
    original = deepcopy(context)

    validate_investigation_context(context)

    assert context == original


def test_real_context_builder_output_passes_validation():
    from src.ai.investigation_context import build_investigation_context
    from src.test_investigation_context_day70 import make_incident

    context = build_investigation_context(make_incident())

    assert validate_investigation_context(context) == []


def test_missing_nested_ioc_field_is_reported():
    context = valid_context()
    del context["iocs"]["indicators"]["hashes"]["sha256"]

    errors = validate_investigation_context(context)

    assert (
        "iocs.indicators.hashes.sha256 must be a list of strings."
        in errors
    )


def test_boolean_is_not_accepted_as_event_count():
    context = valid_context()
    context["incident"]["event_count"] = True

    errors = validate_investigation_context(context)

    assert (
        "incident.event_count must be a non-negative integer."
        in errors
    )
