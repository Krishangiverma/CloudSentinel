"""Day 103 hardening tests for offline CloudTrail replay."""

import pytest

from src.ingestion.cloudtrail import normalize_cloudtrail_record
from src.ingestion.replay import replay_cloudtrail


def sample_record(**overrides):
    record = {
        "eventTime": "2026-10-21T02:30:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {"userName": "synthetic-user"},
    }
    record.update(overrides)
    return record


def test_whitespace_only_required_fields_are_rejected():
    for field in ("eventTime", "eventName", "eventSource"):
        with pytest.raises(ValueError, match="Missing or invalid"):
            normalize_cloudtrail_record(sample_record(**{field: "   "}))


@pytest.mark.parametrize("value", [None, 123, [], {}])
@pytest.mark.parametrize("field", ["eventTime", "eventName", "eventSource"])
def test_non_string_required_fields_are_rejected(field, value):
    with pytest.raises(ValueError, match="Missing or invalid"):
        normalize_cloudtrail_record(sample_record(**{field: value}))


def test_timezone_naive_timestamp_is_rejected():
    with pytest.raises(ValueError, match="timezone"):
        normalize_cloudtrail_record(
            sample_record(eventTime="2026-10-21T02:30:00")
        )


def test_offset_timestamp_is_normalized_to_utc():
    event = normalize_cloudtrail_record(
        sample_record(eventTime="2026-10-21T08:00:00+05:30")
    )
    assert event.timestamp.utcoffset().total_seconds() == 0
    assert event.timestamp.hour == 2
    assert event.timestamp.minute == 30


@pytest.mark.parametrize("identity", [None, {}, {"userName": ""}])
def test_empty_identity_falls_back_to_unknown(identity):
    event = normalize_cloudtrail_record(sample_record(userIdentity=identity))
    assert event.user == "unknown"


@pytest.mark.parametrize("identity", ["not-an-object", [], 42])
def test_non_object_identity_is_rejected(identity):
    with pytest.raises(ValueError, match="userIdentity"):
        normalize_cloudtrail_record(sample_record(userIdentity=identity))


@pytest.mark.parametrize("ip", ["999.999.999.999", "not-an-ip", 123, []])
def test_invalid_source_ip_is_rejected(ip):
    with pytest.raises(ValueError, match="sourceIPAddress"):
        normalize_cloudtrail_record(sample_record(sourceIPAddress=ip))


@pytest.mark.parametrize("ip", [None, "", "-"])
def test_missing_source_ip_uses_na(ip):
    event = normalize_cloudtrail_record(sample_record(sourceIPAddress=ip))
    assert event.ip_address == "N/A"


def test_empty_records_array_returns_empty_result():
    class RecordingPipeline:
        def ingest(self, event):
            raise AssertionError("No events should be ingested")

    assert replay_cloudtrail({"Records": []}, RecordingPipeline()) == []


def test_replay_stops_at_first_invalid_record():
    class RecordingPipeline:
        def __init__(self):
            self.events = []

        def ingest(self, event):
            self.events.append(event)
            return event

    target = RecordingPipeline()
    records = [
        sample_record(),
        {"eventName": "invalid"},
        sample_record(eventName="ListUsers"),
    ]

    with pytest.raises(ValueError, match="record index 1"):
        replay_cloudtrail(records, target)

    assert len(target.events) == 1
    assert target.events[0].event_type == "AWS_CLOUDTRAIL_CONSOLELOGIN"
