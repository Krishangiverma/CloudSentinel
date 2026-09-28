from datetime import datetime

import pytest

from src.analyzers.local_ml_anomaly import (
    FEATURE_NAMES,
    LocalStatisticalAnomalyModel,
    extract_features,
)
from src.models.event import SecurityEvent


def benign_event(message="Routine service heartbeat"):
    return SecurityEvent(
        timestamp=datetime(2026, 1, 1),
        event_type="HEARTBEAT",
        severity="LOW",
        message=message,
        source="system",
        ip_address="N/A",
    )


def test_feature_extraction_is_deterministic():
    event = benign_event()
    assert extract_features(event) == extract_features(event)
    assert len(extract_features(event)) == len(FEATURE_NAMES)


def test_model_requires_at_least_two_training_events():
    model = LocalStatisticalAnomalyModel()
    with pytest.raises(ValueError, match="at least two"):
        model.fit([benign_event()])


def test_model_requires_fit_before_prediction():
    model = LocalStatisticalAnomalyModel()
    with pytest.raises(RuntimeError, match="fitted"):
        model.predict_one(benign_event())


def test_model_fits_benign_events_and_predicts():
    training = [
        benign_event("Routine service heartbeat"),
        benign_event("Routine periodic heartbeat"),
        benign_event("Normal system heartbeat"),
    ]
    model = LocalStatisticalAnomalyModel(threshold=3.0).fit(training)

    result = model.predict_one(benign_event("Routine service heartbeat"))

    assert model.is_fitted
    assert model.training_count == 3
    assert result.anomaly_score >= 0
    assert isinstance(result.is_anomaly, bool)


def test_unusual_message_length_can_trigger_deviation():
    training = [
        benign_event("ok"),
        benign_event("fine"),
        benign_event("ready"),
        benign_event("alive"),
    ]
    model = LocalStatisticalAnomalyModel(threshold=3.0).fit(training)

    result = model.predict_one(
        benign_event("X" * 500)
    )

    assert result.is_anomaly
    assert "message_length" in dict(result.feature_deviations)


def test_model_does_not_mutate_security_event():
    event = benign_event()
    original = (event.message, event.risk_score, event.risk_level)

    model = LocalStatisticalAnomalyModel().fit([
        benign_event("one"),
        benign_event("two"),
        benign_event("three"),
    ])
    model.predict_one(event)

    assert (event.message, event.risk_score, event.risk_level) == original


def test_invalid_thresholds_are_rejected():
    with pytest.raises(ValueError):
        LocalStatisticalAnomalyModel(threshold=0)
    with pytest.raises(ValueError):
        LocalStatisticalAnomalyModel(scale_floor=0)



def test_authentication_failure_feature_recognizes_event_type_and_message():
    failed_type = {
        "event_type": "FAILED_LOGIN",
        "message": "An event occurred",
        "severity": "HIGH",
    }
    failed_message = {
        "event_type": "UNKNOWN",
        "message": "Failed password for user alice",
        "severity": "HIGH",
    }

    type_features = dict(zip(FEATURE_NAMES, extract_features(failed_type)))
    message_features = dict(zip(FEATURE_NAMES, extract_features(failed_message)))

    assert type_features["auth_failure_signal"] == 1.0
    assert message_features["auth_failure_signal"] == 1.0


def test_high_signal_feature_recognizes_security_event_types():
    event = {
        "event_type": "PORT_SCAN",
        "message": "Port scan detected",
        "severity": "HIGH",
    }

    features = dict(zip(FEATURE_NAMES, extract_features(event)))

    assert features["high_signal_event_type"] == 1.0


def test_benign_event_has_no_security_signal_features():
    event = {
        "event_type": "HEARTBEAT",
        "message": "Routine service heartbeat",
        "severity": "LOW",
    }

    features = dict(zip(FEATURE_NAMES, extract_features(event)))

    assert features["auth_failure_signal"] == 0.0
    assert features["high_signal_event_type"] == 0.0
