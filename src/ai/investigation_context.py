"""
CloudSentinel Day 70 - AI Investigation Context.

Builds a deterministic, JSON-serializable investigation context
from an existing CloudSentinel correlated incident.

Important design rules:
    - Does not modify the incident.
    - Does not call an AI/LLM provider.
    - Reuses the existing attack graph and timeline builders.
    - Preserves existing detection / MITRE evidence when present.
    - Uses deterministic ordering.
"""

from copy import deepcopy
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional

from src.attack_graph.attack_graph import (
    AttackGraph,
    build_attack_graph,
)
from src.timeline.incident_timeline import (
    IncidentTimeline,
    build_incident_timeline,
)


CONTEXT_SCHEMA_VERSION = "1.0"


def _json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def _as_event_list(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    events = incident.get("events", [])

    if not isinstance(events, list):
        return []

    return [
        deepcopy(event)
        for event in events
        if isinstance(event, dict)
    ]


def _normalize_iocs(iocs: Any) -> Dict[str, Any]:
    if not isinstance(iocs, dict):
        iocs = {}

    hashes = iocs.get("hashes", {})

    if not isinstance(hashes, dict):
        hashes = {}

    result = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": {
            "md5": [],
            "sha1": [],
            "sha256": [],
        },
    }

    for key in ("ips", "domains", "urls"):
        values = iocs.get(key, [])

        if isinstance(values, list):
            result[key] = sorted(
                {
                    str(value).strip()
                    for value in values
                    if value is not None
                    and str(value).strip()
                }
            )

    for hash_type in ("md5", "sha1", "sha256"):
        values = hashes.get(hash_type, [])

        if isinstance(values, list):
            result["hashes"][hash_type] = sorted(
                {
                    str(value).strip()
                    for value in values
                    if value is not None
                    and str(value).strip()
                }
            )

    return result


def _aggregate_iocs(
    incident: Dict[str, Any],
    events: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:

    aggregated = {
        "ips": set(),
        "domains": set(),
        "urls": set(),
        "hashes": {
            "md5": set(),
            "sha1": set(),
            "sha256": set(),
        },
    }

    sources = []

    incident_iocs = incident.get("iocs")

    if isinstance(incident_iocs, dict):
        sources.append(incident_iocs)

    for event in events:
        event_iocs = event.get("iocs", {})

        if isinstance(event_iocs, dict):
            sources.append(event_iocs)

    for source in sources:
        normalized = _normalize_iocs(source)

        for key in ("ips", "domains", "urls"):
            aggregated[key].update(normalized[key])

        for hash_type in ("md5", "sha1", "sha256"):
            aggregated["hashes"][hash_type].update(
                normalized["hashes"][hash_type]
            )

    return {
        "ips": sorted(aggregated["ips"]),
        "domains": sorted(aggregated["domains"]),
        "urls": sorted(aggregated["urls"]),
        "hashes": {
            "md5": sorted(aggregated["hashes"]["md5"]),
            "sha1": sorted(aggregated["hashes"]["sha1"]),
            "sha256": sorted(aggregated["hashes"]["sha256"]),
        },
    }


def _ioc_summary(iocs: Dict[str, Any]) -> Dict[str, Any]:
    hashes = iocs.get("hashes", {})

    if not isinstance(hashes, dict):
        hashes = {}

    total_hashes = sum(
        len(hashes.get(hash_type, []))
        for hash_type in ("md5", "sha1", "sha256")
    )

    return {
        "total_ips": len(iocs.get("ips", [])),
        "total_domains": len(iocs.get("domains", [])),
        "total_urls": len(iocs.get("urls", [])),
        "total_hashes": total_hashes,
        "has_iocs": bool(
            iocs.get("ips")
            or iocs.get("domains")
            or iocs.get("urls")
            or total_hashes
        ),
    }


def _numeric_risk_score(event: Dict[str, Any]) -> int:
    value = event.get("risk_score", 0) or 0

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _risk_context(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:

    scores = [
        _numeric_risk_score(event)
        for event in events
    ]

    levels = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    threat_intel_scores = []

    for event in events:
        level = str(
            event.get("risk_level", "LOW") or "LOW"
        ).upper()

        if level in levels:
            levels[level] += 1

        ti_score = event.get(
            "threat_intel_score",
            0,
        ) or 0

        try:
            threat_intel_scores.append(int(ti_score))
        except (TypeError, ValueError):
            threat_intel_scores.append(0)

    incident_max = incident.get("max_risk_score")

    if incident_max is not None:
        try:
            max_score = int(incident_max)
        except (TypeError, ValueError):
            max_score = max(scores, default=0)
    else:
        max_score = max(scores, default=0)

    incident_risk_level = incident.get("risk_level")

    if incident_risk_level:
        risk_level = str(
            incident_risk_level
        ).upper()

    elif max_score >= 80:
        risk_level = "CRITICAL"

    elif max_score >= 60:
        risk_level = "HIGH"

    elif max_score >= 35:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    average_score = (
        sum(scores) / len(scores)
        if scores
        else 0.0
    )

    return {
        "max_score": max_score,
        "average_score": round(
            average_score,
            2,
        ),
        "risk_level": risk_level,
        "event_scores": scores,
        "level_counts": levels,
        "max_threat_intel_score": max(
            threat_intel_scores,
            default=0,
        ),
    }


def _collect_existing_values(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
    keys: Iterable[str],
) -> List[Any]:

    values = []

    for key in keys:
        if key in incident:
            values.append(
                deepcopy(incident[key])
            )

    for event in events:
        for key in keys:
            if key in event:
                values.append(
                    deepcopy(event[key])
                )

    return values


def _detections_context(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> List[Any]:

    keys = (
        "detections",
        "detection",
        "detection_evidence",
        "matched_rule",
        "matched_rules",
        "detection_rule",
    )

    return _collect_existing_values(
        incident,
        events,
        keys,
    )


def _mitre_context(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> List[Any]:

    keys = (
        "mitre",
        "mitre_attack",
        "mitre_context",
        "mitre_mappings",
    )

    return _collect_existing_values(
        incident,
        events,
        keys,
    )


def _incident_summary(
    incident: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> Dict[str, Any]:

    attack_pattern = incident.get(
        "attack_pattern",
        "MULTI_EVENT_ACTIVITY",
    )

    if isinstance(attack_pattern, dict):
        attack_pattern_name = attack_pattern.get(
            "name",
            "MULTI_EVENT_ACTIVITY",
        )
    else:
        attack_pattern_name = attack_pattern

    return {
        "incident_id": str(
            incident.get(
                "incident_id",
                "UNKNOWN",
            )
        ),
        "attack_pattern": str(
            attack_pattern_name
        ),
        "status": str(
            incident.get(
                "status",
                "OPEN",
            )
        ).upper(),
        "event_count": len(events),
        "confidence": incident.get(
            "confidence"
        ),
        "response_priority": incident.get(
            "response_priority"
        ),
    }


def build_investigation_context(
    incident: Dict[str, Any],
    *,
    graph: Optional[AttackGraph] = None,
    timeline: Optional[IncidentTimeline] = None,
) -> Dict[str, Any]:

    if not isinstance(incident, dict):
        raise ValueError(
            "incident must be a dictionary."
        )

    events = _as_event_list(incident)

    if graph is None:
        graph = build_attack_graph(incident)

    if timeline is None:
        timeline = build_incident_timeline(
            incident,
            graph=graph,
        )

    iocs = _aggregate_iocs(
        incident,
        events,
    )

    detections = _detections_context(
        incident,
        events,
    )

    mitre_attack = _mitre_context(
        incident,
        events,
    )

    context = {
        "schema_version": CONTEXT_SCHEMA_VERSION,

        "incident": _incident_summary(
            incident,
            events,
        ),

        "risk": _risk_context(
            incident,
            events,
        ),

        "events": _json_safe(events),

        "iocs": {
            "summary": _ioc_summary(iocs),
            "indicators": _json_safe(iocs),
        },

        "detections": _json_safe(
            detections
        ),

        "mitre_attack": _json_safe(
            mitre_attack
        ),

        "attack_chain": _json_safe(
            incident.get(
                "attack_chain",
                {},
            )
        ),

        "attack_graph": _json_safe(
            graph.to_dict()
        ),

        "timeline": _json_safe(
            timeline.to_dict()
        ),
    }

    return _json_safe(context)
