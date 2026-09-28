"""Day 116 regression tests for security-signal anomaly features."""

from src.analyzers.local_ml_anomaly import LocalStatisticalAnomalyModel
from src.evaluate_local_ml_day110 import build_scenarios


def fitted_evaluation_model():
    training, _ = build_scenarios()
    return LocalStatisticalAnomalyModel(threshold=3.0).fit(training)


def test_port_scan_is_detected_and_explained():
    _, cases = build_scenarios()
    model = fitted_evaluation_model()
    sample = next(event for name, event, _ in cases
                  if name == "suspicious_port_scan")

    result = model.predict_one(sample)

    assert result.is_anomaly is True
    assert "high_signal_event_type" in dict(result.feature_deviations)


def test_failed_login_is_detected_and_explained():
    _, cases = build_scenarios()
    model = fitted_evaluation_model()
    sample = next(event for name, event, _ in cases
                  if name == "failed_login")

    result = model.predict_one(sample)

    assert result.is_anomaly is True
    assert "auth_failure_signal" in dict(result.feature_deviations)


def test_benign_scenarios_remain_unflagged_at_default_threshold():
    _, cases = build_scenarios()
    model = fitted_evaluation_model()

    for name, sample, expected_anomaly in cases:
        if not expected_anomaly:
            result = model.predict_one(sample)
            assert result.is_anomaly is False, name


def test_evaluation_training_remains_benign_only():
    training, cases = build_scenarios()

    assert len(training) >= 2
    assert all(label is False for _, _, label in cases[:3])
    assert all(label is True for _, _, label in cases[3:])

def test_indicator_scale_floor_changes_security_signal_deviation():
    _, cases = build_scenarios()
    sample = next(event for name, event, _ in cases
                  if name == "suspicious_port_scan")

    default_model = fitted_evaluation_model()
    custom_model = LocalStatisticalAnomalyModel(
        threshold=3.0,
        indicator_scale_floor=0.5,
    ).fit(build_scenarios()[0])

    default_result = default_model.predict_one(sample)
    custom_result = custom_model.predict_one(sample)

    assert default_result.is_anomaly is True
    assert custom_result.is_anomaly is False
    assert default_result.anomaly_score > custom_result.anomaly_score


def test_non_positive_indicator_scale_floor_is_rejected():
    import pytest

    with pytest.raises(ValueError, match="indicator_scale_floor"):
        LocalStatisticalAnomalyModel(indicator_scale_floor=0)

    with pytest.raises(ValueError, match="indicator_scale_floor"):
        LocalStatisticalAnomalyModel(indicator_scale_floor=-0.1)
