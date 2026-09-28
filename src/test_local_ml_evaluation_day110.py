import pytest

from src.evaluate_local_ml_day110 import (
    build_scenarios,
    metrics,
    run_evaluation,
)


def test_training_set_is_separate_from_labeled_test_cases():
    training, test_cases = build_scenarios()
    assert len(training) >= 2
    assert all(label is False for _, _, label in test_cases[:3])
    assert all(label is True for _, _, label in test_cases[3:])


def test_metrics_calculation():
    result = metrics(
        [True, True, False, False],
        [True, False, True, False],
    )
    assert result["tp"] == 1
    assert result["fn"] == 1
    assert result["fp"] == 1
    assert result["tn"] == 1
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["f1_score"] == 0.5
    assert result["false_positive_rate"] == 0.5


def test_metrics_handle_no_positive_predictions():
    result = metrics([False, False], [False, False])

    assert result["tp"] == 0
    assert result["fp"] == 0
    assert result["tn"] == 2
    assert result["fn"] == 0
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["f1_score"] is None
    assert result["false_positive_rate"] == 0.0


def test_f1_is_zero_when_positive_cases_are_all_missed():
    result = metrics([True, True, False], [False, False, False])

    assert result["precision"] is None
    assert result["recall"] == 0.0
    assert result["f1_score"] == 0.0


def test_metrics_reject_mismatched_lengths():
    with pytest.raises(ValueError, match="equal lengths"):
        metrics([True], [])


def test_evaluation_is_reproducible_and_reports_all_cases():
    first = run_evaluation()
    second = run_evaluation()
    assert first == second
    assert first["training_count"] == 12
    assert len(first["results"]) == 6
    assert "Synthetic demonstration only" in first["warning"]


def test_evaluation_reports_expected_metric_fields():
    report = run_evaluation()
    assert set(report["metrics"]) == {
        "tp", "fp", "tn", "fn",
        "precision", "recall", "f1_score", "false_positive_rate",
    }
