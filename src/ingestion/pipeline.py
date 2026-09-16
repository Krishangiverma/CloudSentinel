"""
CloudSentinel Event Ingestion Pipeline.

Pipeline boundary:

Raw Event
    -> Normalize
    -> Validate
    -> IOC Extraction
    -> Threat Intelligence Enrichment
    -> Risk Analysis
    -> Event Bus
    -> Downstream real-time consumers
"""

from src.ingestion.normalizer import normalize_event
from src.ingestion.validator import validate_event
from src.analyzers.risk_engine import calculate_risk_score
from src.realtime.event_bus import publish

from src.threat_intel.ioc_extractor import extract_iocs
from src.threat_intel.enricher import enrich_iocs


class EventPipeline:
    """
    Canonical entry point for CloudSentinel event ingestion.

    Every successfully normalized and validated event is:

        1. Enriched with IOC information
        2. Enriched with local threat-intelligence context
        3. Enriched with risk information
        4. Published to the real-time event bus
    """

    def __init__(self):
        self.events_processed = 0
        self.events_rejected = 0

    def ingest(self, raw_event):
        """
        Normalize, validate and enrich one raw event.

        Returns:
            validated and enriched SecurityEvent

        Raises:
            EventValidationError
            Any exception raised during normalization,
            validation, IOC enrichment, or risk analysis
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
            # 3. Extract IOCs from the canonical event
            # -------------------------------------------------

            iocs = extract_iocs(event)

            # -------------------------------------------------
            # 4. Enrich extracted IOCs with local context
            # -------------------------------------------------

            threat_intel = enrich_iocs(iocs)

            # -------------------------------------------------
            # 5. Attach IOC and threat-intelligence data
            #
            # We do not modify the SecurityEvent dataclass yet.
            # This keeps existing consumers backward compatible.
            # -------------------------------------------------

            event.iocs = iocs
            event.threat_intel = threat_intel

            # -------------------------------------------------
            # 6. Calculate existing risk score
            #
            # Day 40 does NOT change the risk formula.
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
        # 7. Track successfully processed event
        # -----------------------------------------------------

        self.events_processed += 1

        # -----------------------------------------------------
        # 8. Publish enriched event to existing Event Bus
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
