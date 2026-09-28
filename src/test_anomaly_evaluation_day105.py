import pytest

from src.evaluate_anomaly_day105 import (
    build_dataset,
    calculate_metrics,
    run_evaluation,
)


def test_dataset_contains_normal_and_suspicious_labels():
    dataset = build_dataset()

    assert len(dataset) == 8
    assert {row["label"] for row in dataset} == {True, False}


def test_metrics_calculation():
    result = calculate_metrics(
        [True, True, False, False],
        [True, False, True, False],
    )

    assert result["TP"] == 1
    assert result["FN"] == 1
    assert result["FP"] == 1
    assert result["TN"] == 1
    assert result["precision"] == pytest.approx(0.5)
    assert result["recall"] == pytest.approx(0.5)
    assert result["false_positive_rate"] == pytest.approx(0.5)


def test_undefined_precision_is_none():
    result = calculate_metrics([False, False], [False, False])

    assert result["precision"] is None
    assert result["recall"] is None
    assert result["false_positive_rate"] == 0


def test_mismatched_lengths_raise_value_error():
    with pytest.raises(ValueError, match="equal lengths"):
        calculate_metrics([True], [])


def test_evaluation_is_deterministic():
    first = run_evaluation()
    second = run_evaluation()

    assert first["rule_baseline"] == second["rule_baseline"]
    assert first["day104_anomaly"] == second["day104_anomaly"]
    assert first["anomaly_scores"] == second["anomaly_scores"]


def test_evaluation_returns_results_for_all_events():
    report = run_evaluation()

    assert report["dataset_size"] == 8
    assert len(report["rule_predictions"]) == 8
    assert len(report["anomaly_predictions"]) == 8
    assert len(report["anomaly_scores"]) == 8
    assert report["day104_anomaly"]["FN"] == 1
