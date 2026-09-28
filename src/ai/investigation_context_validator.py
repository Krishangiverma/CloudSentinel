"""Day 91: Harden CloudSentinel investigation-context validation."""

from math import isfinite
from numbers import Real
from typing import Any, List

from src.ai.investigation_context import CONTEXT_SCHEMA_VERSION


def validate_investigation_context(context: Any) -> List[str]:
    """Return validation errors; an empty list means the context is valid."""

    errors: List[str] = []

    if not isinstance(context, dict):
        return ["context must be a dictionary."]

    required_sections = {
        "schema_version": str,
        "incident": dict,
        "risk": dict,
        "events": list,
        "iocs": dict,
        "detections": list,
        "mitre_attack": list,
        "attack_chain": dict,
        "attack_graph": dict,
        "timeline": dict,
    }

    for section, expected_type in required_sections.items():
        if section not in context:
            errors.append(f"Missing required section: {section}.")
        elif not isinstance(context[section], expected_type):
            errors.append(
                f"Section '{section}' must be "
                f"{expected_type.__name__}."
            )

    if errors:
        return errors

    if context["schema_version"] != CONTEXT_SCHEMA_VERSION:
        errors.append(
            "Unsupported schema_version: "
            f"{context['schema_version']}."
        )

    # Incident validation
    incident = context["incident"]

    for field in ("incident_id", "attack_pattern", "status"):
        if field not in incident or not isinstance(incident[field], str):
            errors.append(f"incident.{field} must be a string.")

    event_count = incident.get("event_count")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count < 0
    ):
        errors.append(
            "incident.event_count must be a non-negative integer."
        )

    # Optional incident fields may be absent or None.
    for field in ("confidence", "response_priority"):
        value = incident.get(field)
        if value is not None and not isinstance(value, (str, Real)):
            errors.append(f"incident.{field} must be a string, numeric, or None.")

    # Events must contain dictionaries.
    for index, event in enumerate(context["events"]):
        if not isinstance(event, dict):
            errors.append(f"events[{index}] must be a dictionary.")

    # Risk validation
    risk = context["risk"]

    for field in ("max_score", "average_score"):
        value = risk.get(field)

        if not isinstance(value, Real) or isinstance(value, bool):
            errors.append(f"risk.{field} must be numeric.")
            continue

        if not isfinite(value):
            errors.append(f"risk.{field} must be finite.")
        elif not 0 <= value <= 100:
            errors.append(f"risk.{field} must be between 0 and 100.")

    if not isinstance(risk.get("risk_level"), str):
        errors.append("risk.risk_level must be a string.")

    event_scores = risk.get("event_scores")
    if not isinstance(event_scores, list):
        errors.append("risk.event_scores must be a list.")
    else:
        for index, score in enumerate(event_scores):
            field = f"risk.event_scores[{index}]"

            if not isinstance(score, Real) or isinstance(score, bool):
                errors.append(f"{field} must be numeric.")
            elif not isfinite(score):
                errors.append(f"{field} must be finite.")
            elif not 0 <= score <= 100:
                errors.append(f"{field} must be between 0 and 100.")

    if not isinstance(risk.get("level_counts"), dict):
        errors.append("risk.level_counts must be a dictionary.")

    threat_score = risk.get("max_threat_intel_score")
    if not isinstance(threat_score, int) or isinstance(threat_score, bool):
        errors.append("risk.max_threat_intel_score must be an integer.")

    # IOC validation
    iocs = context["iocs"]

    if not isinstance(iocs.get("summary"), dict):
        errors.append("iocs.summary must be a dictionary.")

    indicators = iocs.get("indicators")
    if not isinstance(indicators, dict):
        errors.append("iocs.indicators must be a dictionary.")
    else:
        for field in ("ips", "domains", "urls"):
            values = indicators.get(field)
            if not isinstance(values, list) or not all(
                isinstance(value, str) for value in values
            ):
                errors.append(
                    f"iocs.indicators.{field} must be a list of strings."
                )

        hashes = indicators.get("hashes")
        if not isinstance(hashes, dict):
            errors.append(
                "iocs.indicators.hashes must be a dictionary."
            )
        else:
            for field in ("md5", "sha1", "sha256"):
                values = hashes.get(field)
                if not isinstance(values, list) or not all(
                    isinstance(value, str) for value in values
                ):
                    errors.append(
                        f"iocs.indicators.hashes.{field} "
                        "must be a list of strings."
                    )

    # Attack graph collections and their individual items.
    attack_graph = context["attack_graph"]

    for field in ("nodes", "edges"):
        values = attack_graph.get(field)

        if not isinstance(values, list):
            errors.append(f"attack_graph.{field} must be a list.")
            continue

        for index, item in enumerate(values):
            if not isinstance(item, dict):
                errors.append(
                    f"attack_graph.{field}[{index}] must be a dictionary."
                )

    # Timeline collections and their individual items.
    timeline = context["timeline"]

    for field in ("entries", "relationships"):
        values = timeline.get(field)

        if not isinstance(values, list):
            errors.append(f"timeline.{field} must be a list.")
            continue

        for index, item in enumerate(values):
            if not isinstance(item, dict):
                errors.append(
                    f"timeline.{field}[{index}] must be a dictionary."
                )

    # attack_chain is required to be a dictionary by the section check.
    # Its internal schema is left unchanged in this hardening pass.

    return errors
