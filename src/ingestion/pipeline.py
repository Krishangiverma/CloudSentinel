"""
CloudSentinel Event Ingestion Pipeline.

Pipeline boundary:

Raw Event
    -> Normalize
    -> Validate
    -> Risk Analysis
    -> Event Bus
    -> Downstream real-time consumers
"""

from src.ingestion.normalizer import normalize_event
from src.ingestion.validator import validate_event
from src.analyzers.risk_engine import calculate_risk_score
from src.realtime.event_bus import publish


class EventPipeline:
    """
    Canonical entry point for CloudSentinel event ingestion.

    Every successfully normalized and validated event is enriched
    with risk information before being published to the real-time
    event bus.
    """

    def __init__(self):
        self.events_processed = 0
        self.events_rejected = 0

    def ingest(self, raw_event):
        """
        Normalize, validate and enrich one raw event.

        Returns:
            validated and risk-enriched SecurityEvent

        Raises:
            EventValidationError
            Any exception raised during normalization, validation,
            or risk analysis
        """

        try:
            # -------------------------------------------------
            # 1. Normalize raw input into canonical event
            # -------------------------------------------------

            event = normalize_event(raw_event)

            # -------------------------------------------------
            # 2. Validate canonical event
            # -------------------------------------------------

            event = validate_event(event)

            # -------------------------------------------------
            # 3. Calculate risk before real-time publication
            # -------------------------------------------------

            risk = calculate_risk_score(
                {
                    "severity": event.severity,
                    "event_type": event.event_type,
                }
            )

            event.risk_score = risk["risk_score"]
            event.risk_level = risk["risk_level"]

        except Exception:
            self.events_rejected += 1
            raise

        # -----------------------------------------------------
        # 4. Track successfully processed event
        # -----------------------------------------------------

        self.events_processed += 1

        # -----------------------------------------------------
        # 5. Publish enriched event to real-time event bus
        # -----------------------------------------------------

        publish(event)

        return event


# Shared pipeline instance for simple application use.
pipeline = EventPipeline()


def ingest_event(raw_event):
    """
    Convenience wrapper around the shared EventPipeline.
    """

    return pipeline.ingest(raw_event)
