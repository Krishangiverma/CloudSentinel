"""
CloudSentinel Event Ingestion Pipeline.

Pipeline boundary:

Raw Event
    -> Normalize
    -> Validate
    -> Downstream processing
"""

from src.ingestion.normalizer import normalize_event
from src.ingestion.validator import validate_event


class EventPipeline:
    """
    Canonical entry point for CloudSentinel event ingestion.
    """

    def __init__(self):
        self.events_processed = 0
        self.events_rejected = 0

    def ingest(self, raw_event):
        """
        Normalize and validate one raw event.

        Returns:
            validated SecurityEvent

        Raises:
            EventValidationError
        """

        try:
            event = normalize_event(raw_event)
            event = validate_event(event)

        except Exception:
            self.events_rejected += 1
            raise

        self.events_processed += 1

        return event


# Shared pipeline instance for simple application use.
pipeline = EventPipeline()


def ingest_event(raw_event):
    """
    Convenience wrapper around the shared EventPipeline.
    """

    return pipeline.ingest(raw_event)
