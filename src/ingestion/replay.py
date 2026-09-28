"""Offline replay of CloudTrail-format JSON through EventPipeline."""

import json
from pathlib import Path

from src.ingestion.cloudtrail import normalize_cloudtrail_record
from src.ingestion.pipeline import pipeline as default_pipeline


def _load_records(source):
    if isinstance(source, (str, Path)):
        with Path(source).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        payload = source

    if isinstance(payload, dict):
        if "Records" in payload:
            records = payload["Records"]
            if not isinstance(records, list):
                raise ValueError("CloudTrail Records must be a JSON array.")
            return records
        return [payload]

    if isinstance(payload, list):
        return payload

    raise ValueError("Replay input must be a JSON object or array.")


def replay_cloudtrail(source, event_pipeline=None):
    """Replay records in order; stop and raise on the first failed record."""
    target = event_pipeline if event_pipeline is not None else default_pipeline
    records = _load_records(source)
    processed = []

    for index, record in enumerate(records):
        try:
            event = normalize_cloudtrail_record(record)
            processed.append(target.ingest(event))
        except Exception as error:
            raise ValueError(
                f"CloudTrail replay failed at record index {index}: {error}"
            ) from error

    return processed
