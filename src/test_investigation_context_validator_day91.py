"""Day 91 regression tests for investigation-context hardening."""

from copy import deepcopy

import pytest

from src.ai.investigation_context_validator import (
    validate_investigation_context,
)
from src.test_investigation_context_validator_day72 import valid_context


@pytest.mark.parametrize(
    ("mutate", "expected_error"),
    [
        (
            lambda context: context["events"].__setitem__(0, None),
            "events[0] must be a dictionary.",
        ),
        (
            lambda context: context["attack_graph"]["nodes"].append("bad-node"),
            "attack_graph.nodes[0] must be a dictionary.",
        ),
        (
            lambda context: context["attack_graph"]["edges"].append("bad-edge"),
            "attack_graph.edges[0] must be a dictionary.",
        ),
        (
            lambda context: context["timeline"]["entries"].append("bad-entry"),
            "timeline.entries[0] must be a dictionary.",
        ),
        (
            lambda context: context["timeline"]["relationships"].append(
                "bad-relationship"
            ),
            "timeline.relationships[0] must be a dictionary.",
        ),
    ],
)
def test_malformed_nested_items_are_rejected(mutate, expected_error):
    context = deepcopy(valid_context())
    mutate(context)

    errors = validate_investigation_context(context)

    assert expected_error in errors


def test_optional_incident_fields_can_be_none():
    context = deepcopy(valid_context())
    context["incident"]["confidence"] = None
    context["incident"]["response_priority"] = None

    assert validate_investigation_context(context) == []


@pytest.mark.parametrize("value", [True, False])
def test_boolean_risk_scores_are_rejected(value):
    context = deepcopy(valid_context())
    context["risk"]["max_score"] = value

    errors = validate_investigation_context(context)

    assert "risk.max_score must be numeric." in errors


def test_malformed_nested_context_does_not_raise():
    context = deepcopy(valid_context())
    context["attack_graph"]["nodes"] = [None, {"node_id": "node-1"}]
    context["timeline"]["entries"] = [[], {}]

    errors = validate_investigation_context(context)

    assert errors
