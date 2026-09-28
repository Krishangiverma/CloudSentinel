import json
from datetime import datetime, timezone

import pytest

from src.ingestion.cloudtrail import normalize_cloudtrail_record
from src.ingestion.replay import replay_cloudtrail
from src.ingestion.pipeline import EventPipeline


def sample_record():
    return {
        "eventTime": "2026-10-21T02:30:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {"userName": "synthetic-user"},
    }


def test_cloudtrail_record_normalizes_canonical_fields():
    record = sample_record()
    event = normalize_cloudtrail_record(record)

    assert event.timestamp == datetime(
        2026, 10, 21, 2, 30, tzinfo=timezone.utc
    )
    assert event.event_type == "AWS_CLOUDTRAIL_ConsoleLogin".upper()
    assert event.source == "aws:cloudtrail/signin.amazonaws.com"
    assert event.ip_address == "192.0.2.10"
    assert event.user == "synthetic-user"
    assert event.raw_evidence is record


def test_missing_source_ip_is_normalized():
    record = sample_record()
    record["sourceIPAddress"] = "-"

    assert normalize_cloudtrail_record(record).ip_address == "N/A"


@pytest.mark.parametrize("field", ["eventTime", "eventName", "eventSource"])
def test_required_fields_are_enforced(field):
    record = sample_record()
    record.pop(field)

    with pytest.raises(ValueError, match="Missing or invalid"):
        normalize_cloudtrail_record(record)


def test_invalid_timestamp_is_rejected():
    record = sample_record()
    record["eventTime"] = "not-a-timestamp"

    with pytest.raises(ValueError, match="eventTime"):
        normalize_cloudtrail_record(record)


def test_invalid_source_ip_is_rejected():
    record = sample_record()
    record["sourceIPAddress"] = "999.999.999.999"

    with pytest.raises(ValueError, match="sourceIPAddress"):
        normalize_cloudtrail_record(record)


def test_invalid_user_identity_is_rejected():
    record = sample_record()
    record["userIdentity"] = "not-an-object"

    with pytest.raises(ValueError, match="userIdentity"):
        normalize_cloudtrail_record(record)


def test_replay_uses_existing_pipeline_and_processes_records_in_order():
    class RecordingPipeline:
        def __init__(self):
            self.events = []

        def ingest(self, event):
            self.events.append(event)
            return event

    target = RecordingPipeline()
    records = [sample_record(), {
        **sample_record(),
        "eventName": "ListUsers",
    }]

    result = replay_cloudtrail({"Records": records}, target)

    assert len(result) == 2
    assert len(target.events) == 2
    assert target.events[0].event_type == "AWS_CLOUDTRAIL_CONSOLELOGIN"
    assert target.events[1].event_type == "AWS_CLOUDTRAIL_LISTUSERS"


def test_replay_reads_local_json_fixture():
    from pathlib import Path

    fixture = (
        Path(__file__).resolve().parent.parent
        / "tests"
        / "fixtures"
        / "cloudtrail_day102.json"
    )

    result = replay_cloudtrail(fixture, EventPipeline())

    assert len(result) == 2
    assert all(event.raw_evidence for event in result)


def test_malformed_json_is_reported(tmp_path):
    fixture = tmp_path / "invalid.json"
    fixture.write_text('{"Records": [', encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        replay_cloudtrail(fixture)


def test_invalid_record_reports_its_index():
    records = [sample_record(), {"eventName": "MissingFields"}]

    with pytest.raises(ValueError, match="record index 1"):
        replay_cloudtrail(records, EventPipeline())


def test_non_array_records_is_rejected():
    with pytest.raises(ValueError, match="Records must be"):
        replay_cloudtrail({"Records": {}}, EventPipeline())


def test_non_object_record_is_rejected():
    with pytest.raises(ValueError, match="record index 0"):
        replay_cloudtrail([None], EventPipeline())
