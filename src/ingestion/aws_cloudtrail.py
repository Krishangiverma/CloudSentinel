"""Optional AWS CloudTrail LookupEvents integration.

This module keeps boto3 optional so offline CloudSentinel replay
continues to work without the AWS SDK or AWS credentials.
"""

from __future__ import annotations

from typing import Any

from src.ingestion.replay import replay_cloudtrail


class CloudTrailClientError(RuntimeError):
    """Raised when CloudTrail lookup or event replay fails."""


def fetch_cloudtrail_events(
    client: Any,
    *,
    start_time,
    end_time,
    event_pipeline=None,
    lookup_attributes=None,
    max_results: int = 50,
):
    """Fetch CloudTrail management events and ingest them into CloudSentinel.

    Args:
        client: A boto3 CloudTrail client or compatible test double.
        start_time: Inclusive start datetime.
        end_time: Exclusive end datetime.
        event_pipeline: Optional existing CloudSentinel pipeline.
        lookup_attributes: Optional list of CloudTrail lookup attributes.
        max_results: Page size requested from AWS, from 1 through 50.

    Returns:
        The list of processed CloudSentinel events.

    Notes:
        This function does not create AWS resources. The supplied client
        determines authentication and AWS region configuration.
    """
    if start_time is None or end_time is None:
        raise ValueError("start_time and end_time are required.")

    if start_time.tzinfo is None or end_time.tzinfo is None:
        raise ValueError("start_time and end_time must be timezone-aware.")

    if start_time >= end_time:
        raise ValueError("start_time must be earlier than end_time.")

    if not isinstance(max_results, int) or isinstance(max_results, bool):
        raise ValueError("max_results must be an integer from 1 through 50.")

    if not 1 <= max_results <= 50:
        raise ValueError("max_results must be between 1 and 50.")

    if lookup_attributes is not None and not isinstance(lookup_attributes, list):
        raise ValueError("lookup_attributes must be a list when provided.")

    records = []
    request = {
        "StartTime": start_time,
        "EndTime": end_time,
        "MaxResults": max_results,
    }

    if lookup_attributes is not None:
        request["LookupAttributes"] = lookup_attributes

    try:
        while True:
            response = client.lookup_events(**request)

            if not isinstance(response, dict):
                raise CloudTrailClientError(
                    "CloudTrail returned an invalid response."
                )

            page_records = response.get("Events", [])
            if not isinstance(page_records, list):
                raise CloudTrailClientError(
                    "CloudTrail response Events must be a list."
                )

            for item in page_records:
                if not isinstance(item, dict):
                    raise CloudTrailClientError(
                        "CloudTrail response contains an invalid event."
                    )

                cloudtrail_event = item.get("CloudTrailEvent")
                if not isinstance(cloudtrail_event, str):
                    raise CloudTrailClientError(
                        "CloudTrail event is missing its JSON payload."
                    )

                import json

                try:
                    parsed = json.loads(cloudtrail_event)
                except json.JSONDecodeError as error:
                    raise CloudTrailClientError(
                        "CloudTrail event contains invalid JSON."
                    ) from error

                if not isinstance(parsed, dict):
                    raise CloudTrailClientError(
                        "CloudTrail event JSON must be an object."
                    )

                records.append(parsed)

            token = response.get("NextToken")
            if not token:
                break

            if not isinstance(token, str) or not token.strip():
                raise CloudTrailClientError(
                    "CloudTrail returned an invalid pagination token."
                )

            request["NextToken"] = token

    except CloudTrailClientError:
        raise
    except Exception as error:
        raise CloudTrailClientError(
            f"CloudTrail lookup failed: {type(error).__name__}: {error}"
        ) from error

    try:
        return replay_cloudtrail(records, event_pipeline=event_pipeline)
    except Exception as error:
        raise CloudTrailClientError(
            f"CloudTrail event ingestion failed: {error}"
        ) from error
