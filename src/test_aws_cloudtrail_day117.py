"""Offline tests for the optional AWS CloudTrail integration."""

from datetime import datetime, timezone
import json

import pytest

from src.ingestion.aws_cloudtrail import (
    CloudTrailClientError,
    fetch_cloudtrail_events,
)


START = datetime(2026, 10, 21, tzinfo=timezone.utc)
END = datetime(2026, 10, 22, tzinfo=timezone.utc)


def record(name="ConsoleLogin"):
    return {
        "eventTime": "2026-10-21T02:30:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": name,
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {"userName": "synthetic-user"},
    }


class FakeCloudTrailClient:
    def __init__(self, pages):
        self.pages = list(pages)
        self.requests = []

    def lookup_events(self, **kwargs):
        self.requests.append(dict(kwargs))
        if not self.pages:
            raise AssertionError("Unexpected extra API call")
        return self.pages.pop(0)


class RecordingPipeline:
    def __init__(self):
        self.events = []

    def ingest(self, event):
        self.events.append(event)
        return event


def response(*records, next_token=None):
    result = {
        "Events": [
            {"CloudTrailEvent": json.dumps(item)}
            for item in records
        ]
    }
    if next_token is not None:
        result["NextToken"] = next_token
    return result


def test_fetches_and_ingests_cloudtrail_events():
    client = FakeCloudTrailClient([response(record())])
    pipeline = RecordingPipeline()

    events = fetch_cloudtrail_events(
        client,
        start_time=START,
        end_time=END,
        event_pipeline=pipeline,
    )

    assert len(events) == 1
    assert events[0].event_type == "AWS_CLOUDTRAIL_CONSOLELOGIN"
    assert len(pipeline.events) == 1
    assert client.requests[0]["StartTime"] == START
    assert client.requests[0]["EndTime"] == END


def test_follows_pagination_token():
    client = FakeCloudTrailClient([
        response(record(), next_token="page-2"),
        response(record("ListUsers")),
    ])

    events = fetch_cloudtrail_events(
        client,
        start_time=START,
        end_time=END,
    )

    assert len(events) == 2
    assert client.requests[1]["NextToken"] == "page-2"


def test_passes_lookup_attributes_and_page_size():
    client = FakeCloudTrailClient([response()])

    fetch_cloudtrail_events(
        client,
        start_time=START,
        end_time=END,
        lookup_attributes=[
            {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
        ],
        max_results=20,
    )

    assert client.requests[0]["MaxResults"] == 20
    assert client.requests[0]["LookupAttributes"][0]["AttributeKey"] == "EventName"


@pytest.mark.parametrize("start,end", [
    (None, END),
    (START, None),
    (datetime(2026, 10, 21), END),
    (START, datetime(2026, 10, 22)),
    (END, START),
])
def test_rejects_invalid_time_range(start, end):
    client = FakeCloudTrailClient([])

    with pytest.raises(ValueError):
        fetch_cloudtrail_events(
            client,
            start_time=start,
            end_time=end,
        )

    assert client.requests == []


@pytest.mark.parametrize("limit", [0, 51, True, 1.5, "10"])
def test_rejects_invalid_page_size(limit):
    client = FakeCloudTrailClient([])

    with pytest.raises(ValueError, match="max_results"):
        fetch_cloudtrail_events(
            client,
            start_time=START,
            end_time=END,
            max_results=limit,
        )

    assert client.requests == []


def test_wraps_client_errors_without_leaking_credentials():
    class FailingClient:
        def lookup_events(self, **kwargs):
            raise RuntimeError("request failed")

    with pytest.raises(CloudTrailClientError, match="lookup failed"):
        fetch_cloudtrail_events(
            FailingClient(),
            start_time=START,
            end_time=END,
        )


def test_rejects_invalid_cloudtrail_json():
    client = FakeCloudTrailClient([
        {"Events": [{"CloudTrailEvent": "{invalid-json"}]}
    ])

    with pytest.raises(CloudTrailClientError, match="invalid JSON"):
        fetch_cloudtrail_events(
            client,
            start_time=START,
            end_time=END,
        )


def test_rejects_non_object_cloudtrail_json():
    client = FakeCloudTrailClient([
        {"Events": [{"CloudTrailEvent": "[]"}]}
    ])

    with pytest.raises(CloudTrailClientError, match="must be an object"):
        fetch_cloudtrail_events(
            client,
            start_time=START,
            end_time=END,
        )


def test_rejects_malformed_page_response():
    client = FakeCloudTrailClient([{"Events": {}}])

    with pytest.raises(CloudTrailClientError, match="Events must be a list"):
        fetch_cloudtrail_events(
            client,
            start_time=START,
            end_time=END,
        )


def test_empty_response_returns_no_events():
    client = FakeCloudTrailClient([response()])

    assert fetch_cloudtrail_events(
        client,
        start_time=START,
        end_time=END,
    ) == []
