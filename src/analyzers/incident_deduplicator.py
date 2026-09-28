"""
CloudSentinel Day 66 - Incident Deduplication.

Deduplicates investigation-ready incidents into a single canonical case
when they represent the same activity based on:

    1. shared source identity OR shared user identity
    2. temporal overlap / proximity
    3. deterministic evidence merging

The module is intentionally separate from confidence scoring.

Confidence asks:
    "How strongly does the evidence support this incident?"

Deduplication asks:
    "Do these candidate incidents represent the same case?"
"""

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


DEFAULT_DEDUP_WINDOW_SECONDS = 300


# ============================================================
# TIMESTAMP HELPERS
# ============================================================

def _parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse a CloudSentinel timestamp safely."""

    if value is None:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip()

        if not text:
            return None

        text = text.replace("Z", "+00:00")

        try:
            parsed = datetime.fromisoformat(text)
        except (TypeError, ValueError):
            return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _event_time_bounds(
    incident: Dict[str, Any],
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Return deterministic first/last timestamps for an incident."""

    events = incident.get("events", [])

    if isinstance(events, list):
        timestamps = [
            _parse_timestamp(event.get("timestamp"))
            for event in events
            if isinstance(event, dict)
        ]

        timestamps = [
            timestamp
            for timestamp in timestamps
            if timestamp is not None
        ]

        if timestamps:
            return min(timestamps), max(timestamps)

    first_seen = _parse_timestamp(incident.get("first_seen"))
    last_seen = _parse_timestamp(incident.get("last_seen"))

    return first_seen, last_seen


# ============================================================
# IDENTITY HELPERS
# ============================================================

def _normalise_identity(value: Any) -> Optional[str]:
    """Normalize an identity while rejecting placeholder values."""

    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    if text.upper() in {
        "UNKNOWN",
        "N/A",
        "NONE",
        "NULL",
        "MULTIPLE",
    }:
        return None

    return text


def _incident_source_ips(incident: Dict[str, Any]) -> Set[str]:
    """Return normalized source IP identities."""

    values = incident.get("source_ips", [])

    if not isinstance(values, list):
        values = []

    result = {
        value
        for value in (
            _normalise_identity(item)
            for item in values
        )
        if value is not None
    }

    ip_address = _normalise_identity(
        incident.get("ip_address")
    )

    if ip_address is not None:
        result.add(ip_address)

    return result


def _incident_users(incident: Dict[str, Any]) -> Set[str]:
    """Return normalized user identities."""

    values = incident.get("users", [])

    if not isinstance(values, list):
        values = []

    return {
        str(value).strip().lower()
        for value in values
        if _normalise_identity(value) is not None
    }


# ============================================================
# EVENT HELPERS
# ============================================================

def _event_identity(event: Dict[str, Any]) -> Tuple[str, str]:
    """
    Return a deterministic event identity.

    Event IDs are preferred. When an ID is unavailable, the
    timestamp/type/message tuple prevents accidental duplication.
    """

    if "id" in event and event.get("id") is not None:
        return ("id", str(event.get("id")))

    return (
        "fingerprint",
        "|".join(
            [
                str(event.get("timestamp", "")),
                str(event.get("event_type", "")),
                str(event.get("ip_address", "")),
                str(event.get("user", "")),
                str(event.get("message", "")),
            ]
        ),
    )


def _merge_events(
    incidents: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge incident events without duplicating evidence."""

    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}

    for incident in incidents:
        events = incident.get("events", [])

        if not isinstance(events, list):
            continue

        for event in events:
            if not isinstance(event, dict):
                continue

            key = _event_identity(event)

            if key not in merged:
                merged[key] = dict(event)

    return sorted(
        merged.values(),
        key=lambda event: (
            str(event.get("timestamp", "")),
            str(event.get("id", "")),
        ),
    )


# ============================================================
# TEMPORAL RELATIONSHIP
# ============================================================

def _temporally_related(
    first: Dict[str, Any],
    second: Dict[str, Any],
    window_seconds: float,
) -> bool:
    """
    Return True when incident time ranges overlap or are close.

    This handles both:
        [10:00, 10:03] + [10:02, 10:05]
    and:
        [10:00, 10:03] + [10:06, 10:08]
    """

    first_start, first_end = _event_time_bounds(first)
    second_start, second_end = _event_time_bounds(second)

    if (
        first_start is None
        or first_end is None
        or second_start is None
        or second_end is None
    ):
        return False

    if window_seconds < 0:
        return False

    if first_end < second_start:
        gap = (second_start - first_end).total_seconds()
        return gap <= window_seconds

    if second_end < first_start:
        gap = (first_start - second_end).total_seconds()
        return gap <= window_seconds

    # Time ranges overlap.
    return True


# ============================================================
# INCIDENT RELATIONSHIP
# ============================================================

def incidents_are_related(
    first: Dict[str, Any],
    second: Dict[str, Any],
    window_seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> bool:
    """
    Determine whether two incidents represent one candidate case.

    Requirements:
        - incidents must be temporally related
        - they must share a source IP OR user identity
    """

    if not isinstance(first, dict):
        return False

    if not isinstance(second, dict):
        return False

    if not _temporally_related(
        first,
        second,
        window_seconds,
    ):
        return False

    shared_ips = (
        _incident_source_ips(first)
        & _incident_source_ips(second)
    )

    if shared_ips:
        return True

    shared_users = (
        _incident_users(first)
        & _incident_users(second)
    )

    return bool(shared_users)


# ============================================================
# FIELD MERGING
# ============================================================

def _merge_lists(values: Iterable[Any]) -> List[Any]:
    """Deterministically merge scalar/list values."""

    result = set()

    for value in values:
        if isinstance(value, list):
            for item in value:
                result.add(str(item))
        elif value is not None:
            result.add(str(value))

    return sorted(result)


def _merge_iocs(
    incidents: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge IOC collections deterministically."""

    ips: Set[str] = set()
    domains: Set[str] = set()
    hashes = {
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
    }

    for incident in incidents:
        iocs = incident.get("iocs", {})

        if not isinstance(iocs, dict):
            continue

        for value in iocs.get("ips", []) or []:
            ips.add(str(value))

        for value in iocs.get("domains", []) or []:
            domains.add(str(value))

        incident_hashes = iocs.get("hashes", {})

        if isinstance(incident_hashes, dict):
            for hash_type in hashes:
                for value in incident_hashes.get(
                    hash_type,
                    [],
                ) or []:
                    hashes[hash_type].add(str(value))

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "hashes": {
            key: sorted(value)
            for key, value in hashes.items()
        },
    }


def _merge_relationships(
    incidents: Iterable[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge correlation relationships without duplicates."""

    relationships = {}

    for incident in incidents:
        correlation = incident.get("correlation", {})

        if not isinstance(correlation, dict):
            continue

        values = correlation.get("relationships", [])

        if not isinstance(values, list):
            continue

        for relationship in values:
            if not isinstance(relationship, dict):
                continue

            source = relationship.get(
                "event_id",
                relationship.get("source_event_id"),
            )

            target = relationship.get(
                "related_event_id",
                relationship.get("target_event_id"),
            )

            key = (
                str(source),
                str(target),
            )

            relationships[key] = dict(relationship)

    return [
        relationships[key]
        for key in sorted(relationships)
    ]


def _merge_incident_metadata(
    incidents: List[Dict[str, Any]],
    merged_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the merged incident's common metadata."""

    source_ips = set()
    users = set()

    for incident in incidents:
        source_ips.update(
            _incident_source_ips(incident)
        )
        users.update(
            _incident_users(incident)
        )

    event_types = {}

    for event in merged_events:
        event_type = str(
            event.get("event_type", "UNKNOWN")
        ).upper()

        event_types[event_type] = (
            event_types.get(event_type, 0) + 1
        )

    risk_scores = [
        event.get("risk_score", 0) or 0
        for event in merged_events
    ]

    threat_scores = [
        event.get("threat_intel_score", 0) or 0
        for event in merged_events
    ]

    critical_count = sum(
        1
        for event in merged_events
        if str(
            event.get("risk_level", "")
        ).upper() == "CRITICAL"
    )

    high_count = sum(
        1
        for event in merged_events
        if str(
            event.get("risk_level", "")
        ).upper() == "HIGH"
    )

    timestamps = [
        event.get("timestamp")
        for event in merged_events
        if event.get("timestamp") is not None
    ]

    return {
        "source_ips": sorted(source_ips),
        "users": sorted(users),
        "event_types": event_types,
        "event_count": len(merged_events),
        "max_risk_score": max(risk_scores, default=0),
        "max_threat_intel_score": max(
            threat_scores,
            default=0,
        ),
        "total_threat_intel_score": sum(
            threat_scores
        ),
        "critical_event_count": critical_count,
        "high_risk_event_count": high_count,
        "first_seen": min(timestamps) if timestamps else None,
        "last_seen": max(timestamps) if timestamps else None,
        "iocs": _merge_iocs(incidents),
    }


# ============================================================
# INCIDENT MERGE
# ============================================================

def merge_incidents(
    incidents: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Merge multiple related incidents into one case.

    The earliest incident ID becomes the canonical ID.
    Derived confidence is recalculated from merged evidence.
    """

    candidates = [
        incident
        for incident in incidents
        if isinstance(incident, dict)
    ]

    if not candidates:
        raise ValueError(
            "At least one incident is required."
        )

    if len(candidates) == 1:
        return dict(candidates[0])

    candidates.sort(
        key=lambda incident: (
            str(incident.get("incident_id", "")),
        )
    )

    merged_events = _merge_events(candidates)
    metadata = _merge_incident_metadata(
        candidates,
        merged_events,
    )

    relationships = _merge_relationships(candidates)

    attack_chain_values = [
        incident.get("attack_chain", {})
        for incident in candidates
        if isinstance(
            incident.get("attack_chain", {}),
            dict,
        )
    ]

    stage_count = max(
        [
            int(
                value.get("stage_count", 0) or 0
            )
            for value in attack_chain_values
        ],
        default=0,
    )

    complete_attack_chain = any(
        value.get("complete_attack_chain", False)
        for value in attack_chain_values
    )

    merged = dict(candidates[0])

    merged.update(metadata)

    merged["incident_id"] = min(
        str(
            incident.get(
                "incident_id",
                "INC-UNKNOWN",
            )
        )
        for incident in candidates
    )

    merged["events"] = merged_events

    merged["correlation"] = dict(
        candidates[0].get("correlation", {})
        if isinstance(
            candidates[0].get("correlation", {}),
            dict,
        )
        else {}
    )

    merged["correlation"]["relationships"] = (
        relationships
    )

    merged["attack_chain"] = {
        "stage_count": stage_count,
        "complete_attack_chain": complete_attack_chain,
    }

    merged["deduplication"] = {
        "merged": True,
        "source_incident_ids": sorted(
            str(
                incident.get(
                    "incident_id",
                    "",
                )
            )
            for incident in candidates
        ),
        "merged_incident_count": len(candidates),
        "merged_event_count": len(merged_events),
    }

    # Confidence is recalculated from the merged evidence.
    try:
        from .confidence_scorer import calculate_confidence

        confidence = calculate_confidence(
            {
                "event_count": metadata["event_count"],
                "events": merged_events,
                "source_ips": metadata["source_ips"],
                "users": metadata["users"],
                "max_risk_score": metadata[
                    "max_risk_score"
                ],
                "max_threat_intel_score": metadata[
                    "max_threat_intel_score"
                ],
                "critical_event_count": metadata[
                    "critical_event_count"
                ],
                "high_risk_event_count": metadata[
                    "high_risk_event_count"
                ],
                "attack_chain": merged["attack_chain"],
                "correlation": merged["correlation"],
            }
        )

        merged["confidence_score"] = confidence["score"]
        merged["confidence_level"] = confidence["level"]
        merged["confidence"] = confidence

    except (ImportError, TypeError, ValueError):
        # Deduplication must never destroy an otherwise valid incident
        # simply because confidence recalculation cannot be performed.
        pass

    return merged


# ============================================================
# PUBLIC DEDUPLICATION ENGINE
# ============================================================

def deduplicate_incidents(
    incidents: Iterable[Dict[str, Any]],
    window_seconds: float = DEFAULT_DEDUP_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Deduplicate related incidents deterministically.

    Incidents are merged transitively:

        A related to B
        B related to C

    produces one case containing A + B + C.
    """

    if window_seconds < 0:
        raise ValueError(
            "Deduplication window cannot be negative."
        )

    working = [
        dict(incident)
        for incident in incidents
        if isinstance(incident, dict)
    ]

    if not working:
        return []

    # Stable ordering before grouping.
    working.sort(
        key=lambda incident: (
            _event_time_bounds(incident)[0]
            or datetime.max.replace(
                tzinfo=timezone.utc
            ),
            str(incident.get("incident_id", "")),
        )
    )

    groups: List[List[Dict[str, Any]]] = []

    for incident in working:
        matched_group = None

        for group in groups:
            if any(
                incidents_are_related(
                    incident,
                    existing,
                    window_seconds,
                )
                for existing in group
            ):
                matched_group = group
                break

        if matched_group is None:
            groups.append([incident])
        else:
            matched_group.append(incident)

    result = [
        merge_incidents(group)
        for group in groups
    ]

    result.sort(
        key=lambda incident: (
            _event_time_bounds(incident)[0]
            or datetime.max.replace(
                tzinfo=timezone.utc
            ),
            str(incident.get("incident_id", "")),
        )
    )

    return result


__all__ = [
    "DEFAULT_DEDUP_WINDOW_SECONDS",
    "incidents_are_related",
    "merge_incidents",
    "deduplicate_incidents",
]
