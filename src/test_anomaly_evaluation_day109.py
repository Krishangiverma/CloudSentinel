"""Tests for Day 109 scenario-isolated synthetic evaluation."""

from src.evaluate_anomaly_day109 import (
    THRESHOLDS,
    build_scenarios,
    run_scenario_evaluation,
)


def test_scenarios_have_both_labels_and_unique_ids():
    scenarios = build_scenarios()

    assert len(scenarios) == 7
    assert {scenario["label"] for scenario in scenarios} == {True, False}
    assert len({scenario["id"] for scenario in scenarios}) == len(scenarios)


def test_benign_repeated_ip_batch_is_scored_independently():
    report = run_scenario_evaluation()

    for threshold in THRESHOLDS:
        details = report["reports"][threshold]["details"]
        scenario = next(
            item for item in details
            if item["id"] == "benign_repeated_ip"
        )
        assert scenario["scores"] == [25, 25, 25, 25]
        assert scenario["scenario_flagged"] is False


def test_isolated_failed_login_threshold_sensitivity():
    report = run_scenario_evaluation()

    for threshold, expected in ((30, True), (40, False), (60, False)):
        details = report["reports"][threshold]["details"]
        scenario = next(
            item for item in details
            if item["id"] == "isolated_failed_login"
        )
        assert scenario["scores"] == [35]
        assert scenario["scenario_flagged"] is expected


def test_port_scan_and_intrusion_have_high_signal_scores():
    report = run_scenario_evaluation()

    for threshold in THRESHOLDS:
        details = report["reports"][threshold]["details"]
        port_scan = next(
            item for item in details if item["id"] == "high_signal_port_scan"
        )
        intrusion = next(
            item for item in details
            if item["id"] == "suspicious_event_without_ip"
        )

        assert port_scan["scores"] == [45]
        assert intrusion["scores"] == [45]
        expected_flag = threshold <= 45
        assert port_scan["scenario_flagged"] is expected_flag
        assert intrusion["scenario_flagged"] is expected_flag


def test_metrics_account_for_every_scenario():
    report = run_scenario_evaluation()

    for threshold in THRESHOLDS:
        metrics = report["reports"][threshold]["metrics"]
        assert (
            metrics["TP"] + metrics["FP"]
            + metrics["TN"] + metrics["FN"]
        ) == report["scenario_count"]


def test_evaluation_is_deterministic():
    first = run_scenario_evaluation()
    second = run_scenario_evaluation()

    for threshold in THRESHOLDS:
        assert (
            first["reports"][threshold]["metrics"]
            == second["reports"][threshold]["metrics"]
        )


def test_scenarios_do_not_share_event_objects():
    scenarios = build_scenarios()

    assert len({
        id(event)
        for scenario in scenarios
        for event in scenario["events"]
    }) == sum(len(scenario["events"]) for scenario in scenarios)
