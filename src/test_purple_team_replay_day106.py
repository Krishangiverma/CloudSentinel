"""Day 106: Safe, deterministic local purple-team replay tests."""

import pytest

from src.analyzers.anomaly_detector import detect_anomalies
from src.ingestion.replay import replay_cloudtrail


class FakePipeline:
    """Capture replayed events without database or network side effects."""

    def __init__(self):
        self.events = []

    def ingest(self, event):
        self.events.append(event)
        return event


def cloudtrail_record(
    timestamp,
    source_ip="198.51.100.10",
    error_message=None,
):
    """Build a synthetic CloudTrail-style login event."""

    record = {
        "eventTime": timestamp,
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "sourceIPAddress": source_ip,
        "userIdentity": {
            "type": "IAMUser",
            "userName": "synthetic-test-user",
        },
    }

    if error_message is not None:
        record["errorCode"] = "NotAuthorizedException"
        record["errorMessage"] = error_message

    return record


def failed_login_scenario():
    """Three synthetic failures from one address, in timestamp order."""

    return {
        "Records": [
            cloudtrail_record(
                "2026-10-22T10:00:00Z",
                error_message="Failed login: authentication failure",
            ),
            cloudtrail_record(
                "2026-10-22T10:00:10Z",
                error_message="Failed login: authentication failure",
            ),
            cloudtrail_record(
                "2026-10-22T10:00:20Z",
                error_message="Failed login: authentication failure",
            ),
        ]
    }


def test_benign_login_replays_without_anomaly():
    pipeline = FakePipeline()
    scenario = {
        "Records": [
            cloudtrail_record("2026-10-22T10:00:00Z")
        ]
    }

    events = replay_cloudtrail(scenario, event_pipeline=pipeline)
    results = detect_anomalies(events)

    assert len(events) == 1
    assert len(pipeline.events) == 1
    assert results[0].is_anomaly is False
    assert results[0].anomaly_score == 0


def test_repeated_failed_logins_receive_explainable_anomaly_scores():
    pipeline = FakePipeline()

    events = replay_cloudtrail(
        failed_login_scenario(),
        event_pipeline=pipeline,
    )
    results = detect_anomalies(events, threshold=40)

    assert len(events) == 3
    assert len(pipeline.events) == 3

    for result in results:
        assert result.is_anomaly is True
        assert result.anomaly_score == 40
        assert "authentication_failure_signal" in result.reasons
        assert "repeated_source_ip_in_batch" in result.reasons


def test_replay_preserves_event_order():
    pipeline = FakePipeline()
    scenario = failed_login_scenario()

    events = replay_cloudtrail(scenario, event_pipeline=pipeline)

    assert [
        event.timestamp.isoformat()
        for event in events
    ] == [
        "2026-10-22T10:00:00+00:00",
        "2026-10-22T10:00:10+00:00",
        "2026-10-22T10:00:20+00:00",
    ]


def test_repeated_replay_produces_identical_detection_results():
    scenario = failed_login_scenario()

    first_events = replay_cloudtrail(
        scenario, event_pipeline=FakePipeline()
    )
    second_events = replay_cloudtrail(
        scenario, event_pipeline=FakePipeline()
    )

    first_results = detect_anomalies(first_events, threshold=40)
    second_results = detect_anomalies(second_events, threshold=40)

    def signature(results):
        return [
            (
                result.anomaly_score,
                result.is_anomaly,
                result.reasons,
                result.event_type,
                result.source_ip,
            )
            for result in results
        ]

    assert signature(first_results) == signature(second_results)


def test_malformed_record_fails_at_its_index():
    pipeline = FakePipeline()
    scenario = {
        "Records": [
            cloudtrail_record("2026-10-22T10:00:00Z"),
            {"eventTime": "2026-10-22T10:00:10Z"},
        ]
    }

    with pytest.raises(ValueError, match="record index 1"):
        replay_cloudtrail(scenario, event_pipeline=pipeline)

    # The first record succeeds; the second fails before ingestion.
    assert len(pipeline.events) == 1
