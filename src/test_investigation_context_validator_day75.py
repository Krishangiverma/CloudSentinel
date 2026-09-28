"""Day 75 tests for risk-score boundaries and numeric integrity."""

from copy import deepcopy

import pytest

from src.test_investigation_context_validator_day72 import valid_context
from src.ai.investigation_context_validator import (
    validate_investigation_context,
)


@pytest.mark.parametrize("score", [-1, 101, float("nan"), float("inf"), -float("inf")])
def test_max_risk_score_rejects_out_of_range_or_non_finite_values(score):
    context = deepcopy(valid_context())
    context["risk"]["max_score"] = score

    errors = validate_investigation_context(context)

    assert any(
        "risk.max_score" in error
        and ("between 0 and 100" in error or "finite" in error)
        for error in errors
    )


@pytest.mark.parametrize("score", [-1, 101, float("nan"), float("inf")])
def test_average_risk_score_rejects_out_of_range_or_non_finite_values(score):
    context = deepcopy(valid_context())
    context["risk"]["average_score"] = score

    errors = validate_investigation_context(context)

    assert any(
        "risk.average_score" in error
        and ("between 0 and 100" in error or "finite" in error)
        for error in errors
    )


@pytest.mark.parametrize("score", [-1, 101, float("nan"), float("inf")])
def test_event_scores_reject_invalid_numeric_values(score):
    context = deepcopy(valid_context())
    context["risk"]["event_scores"] = [75, score]

    errors = validate_investigation_context(context)

    assert any("risk.event_scores[1]" in error for error in errors)


def test_valid_boundary_risk_scores_are_accepted():
    context = deepcopy(valid_context())
    context["risk"]["max_score"] = 100
    context["risk"]["average_score"] = 0
    context["risk"]["event_scores"] = [0, 100]

    errors = validate_investigation_context(context)

    assert errors == []
