"""
CloudSentinel Event Ingestion Pipeline.

Pipeline:
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

    Successfully published events increment events_processed.
    Any event that fails during processing or publishing
    increments events_rejected.
    """

    def __init__(self, ml_model=None):
        self.events_processed = 0
        self.events_rejected = 0
        self.ml_model = ml_model
        self.ml_prediction_errors = 0
        self.ml_last_error = None

    def ingest(self, raw_event):
        """
        Normalize, validate, enrich, and publish one event.

        Returns:
            SecurityEvent: The successfully published event.

        Raises:
            EventValidationError or the original exception when
            normalization, validation, enrichment, risk analysis,
            or publishing fails.
        """

        try:
            # 1. Normalize the raw input.
            event = normalize_event(raw_event)

            # 2. Validate the canonical event.
            event = validate_event(event)

            # 3. Extract indicators of compromise.
            iocs = extract_iocs(event)

            # 4. Enrich the indicators with local threat intelligence.
            threat_intel = enrich_iocs(iocs)

            # 5. Attach enrichment information to the event.
            event.iocs = iocs
            event.threat_intel = threat_intel

            # 6. Calculate the final risk score.
            risk = calculate_risk_score(
                {
                    "severity": event.severity,
                    "event_type": event.event_type,
                    "threat_intel": event.threat_intel,
                }
            )

            event.risk_score = risk["risk_score"]
            event.risk_level = risk["risk_level"]
            event.threat_intel_score = risk["threat_intel_score"]

            # 7. Optional ML anomaly enrichment.
            # ML failures must not change existing risk scoring or reject events.
            if self.ml_model is not None:
                try:
                    result = self.ml_model.predict_one(event)
                    event.ml_anomaly_score = float(result.anomaly_score)
                    event.ml_is_anomaly = bool(result.is_anomaly)
                    event.ml_feature_deviations = dict(
                        result.feature_deviations
                    )
                    self.ml_last_error = None
                except Exception as error:
                    self.ml_prediction_errors += 1
                    self.ml_last_error = (
                        f"{type(error).__name__}: {error}"
                    )

            # 8. Publish the enriched event.
            # A publishing exception is handled by this try/except.
            publish(event)

        except Exception:
            self.events_rejected += 1
            raise

        # Count the event as processed only after publish returns.
        self.events_processed += 1

        return event


# Shared pipeline instance for application use.
pipeline = EventPipeline()


def ingest_event(raw_event):
    """
    Convenience wrapper around the shared EventPipeline.
    """
    return pipeline.ingest(raw_event)
