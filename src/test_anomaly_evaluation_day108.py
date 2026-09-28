"""Day 108 tests for threshold-sensitivity evaluation."""

import pytest

from src.evaluate_anomaly_day108 import (
    THRESHOLDS,
    build_extended_dataset,
    run_threshold_evaluation,
)


def test_extended_dataset_adds_four_benign_repeated_ip_events():
    dataset = build_extended_dataset()

    assert len(dataset) == 12
    assert sum(row["label"] for row in dataset) == 4
    assert sum(not row["label"] for row in dataset) == 8


def test_benign_repeated_ip_events_receive_frequency_scores():
    report = run_threshold_evaluation()

    for index in range(8, 12):
        for threshold in THRESHOLDS:
            assert report["reports"][threshold]["scores"][index] == 25
            assert report["reports"][threshold]["predictions"][index] is False


def test_lower_threshold_detects_isolated_failed_login():
    report = run_threshold_evaluation()

    # The isolated failed login is event index 4 in the Day 105 dataset.
    assert report["reports"][30]["scores"][4] == 35
    assert report["reports"][30]["predictions"][4] is True
    assert report["reports"][40]["predictions"][4] is False
    assert report["reports"][60]["predictions"][4] is False


def test_lower_threshold_does_not_reduce_true_positive_count():
    report = run_threshold_evaluation()

    assert (
        report["reports"][30]["metrics"]["TP"]
        >= report["reports"][40]["metrics"]["TP"]
        >= report["reports"][60]["metrics"]["TP"]
    )


def test_threshold_changes_classification_not_scores():
    report = run_threshold_evaluation()
    score_lists = [
        report["reports"][threshold]["scores"]
        for threshold in THRESHOLDS
    ]

    assert score_lists[0] == score_lists[1] == score_lists[2]


def test_evaluation_is_deterministic():
    first = run_threshold_evaluation()
    second = run_threshold_evaluation()

    for threshold in THRESHOLDS:
        assert (
            first["reports"][threshold]["metrics"]
            == second["reports"][threshold]["metrics"]
        )


def test_dataset_has_both_labels():
    dataset = build_extended_dataset()

    assert {row["label"] for row in dataset} == {True, False}


def test_invalid_threshold_behavior_remains_owned_by_detector():
    from src.analyzers.anomaly_detector import detect_anomalies

    with pytest.raises(ValueError, match="threshold"):
        detect_anomalies([], threshold=101)
