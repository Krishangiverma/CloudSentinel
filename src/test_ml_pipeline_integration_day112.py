from datetime import datetime

from src.analyzers.local_ml_anomaly import LocalStatisticalAnomalyModel
from src.ingestion.pipeline import EventPipeline
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


def raw_event(message="Routine service heartbeat"):
    return {
        "event_type": "HEARTBEAT",
        "severity": "LOW",
        "message": message,
        "source": "system",
        "ip_address": "N/A",
    }


def fitted_model():
    return LocalStatisticalAnomalyModel(threshold=3.0).fit([
        benign_event("Routine service heartbeat"),
        benign_event("Routine periodic heartbeat"),
        benign_event("Normal system heartbeat"),
    ])


def test_ml_is_disabled_by_default(monkeypatch):
    import src.ingestion.pipeline as module
    monkeypatch.setattr(module, "publish", lambda event: None)

    event = EventPipeline().ingest(raw_event())

    assert event.ml_anomaly_score is None
    assert event.ml_is_anomaly is None
    assert event.ml_feature_deviations == {}


def test_fitted_ml_model_enriches_event(monkeypatch):
    import src.ingestion.pipeline as module
    monkeypatch.setattr(module, "publish", lambda event: None)

    pipeline = EventPipeline(ml_model=fitted_model())
    event = pipeline.ingest(raw_event("X" * 500))

    assert event.ml_anomaly_score is not None
    assert event.ml_anomaly_score >= 0
    assert event.ml_is_anomaly is True
    assert "message_length" in event.ml_feature_deviations
    assert pipeline.events_processed == 1
    assert pipeline.events_rejected == 0


def test_ml_does_not_change_existing_risk_score(monkeypatch):
    import src.ingestion.pipeline as module
    monkeypatch.setattr(module, "publish", lambda event: None)

    raw = {
        "event_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message": "Multiple failed login attempts",
        "source": "auth.log",
        "ip_address": "192.168.1.50",
    }

    without_ml = EventPipeline().ingest(raw)
    with_ml = EventPipeline(ml_model=fitted_model()).ingest(raw)

    assert with_ml.risk_score == without_ml.risk_score
    assert with_ml.risk_level == without_ml.risk_level
    assert with_ml.threat_intel_score == without_ml.threat_intel_score


def test_ml_prediction_failure_does_not_reject_event(monkeypatch):
    import src.ingestion.pipeline as module
    monkeypatch.setattr(module, "publish", lambda event: None)

    class BrokenModel:
        def predict_one(self, event):
            raise RuntimeError("simulated ML failure")

    pipeline = EventPipeline(ml_model=BrokenModel())
    event = pipeline.ingest(raw_event())

    assert event.risk_score is not None
    assert event.ml_anomaly_score is None
    assert event.ml_is_anomaly is None
    assert pipeline.events_processed == 1
    assert pipeline.events_rejected == 0
    assert pipeline.ml_prediction_errors == 1
    assert "simulated ML failure" in pipeline.ml_last_error


def test_publish_failure_still_counts_as_rejected(monkeypatch):
    import pytest
    import src.ingestion.pipeline as module

    def fail_publish(event):
        raise RuntimeError("simulated publish failure")

    monkeypatch.setattr(module, "publish", fail_publish)
    pipeline = EventPipeline(ml_model=fitted_model())

    with pytest.raises(RuntimeError, match="simulated publish failure"):
        pipeline.ingest(raw_event())

    assert pipeline.events_processed == 0
    assert pipeline.events_rejected == 1
